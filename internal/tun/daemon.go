//go:build !hopway_native && (darwin || linux)

package tun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// The TUN service is an optional, permanently installed root daemon that
// replaces the per-start password prompt. It does one thing: create the
// device and hand it over, and only to the user who installed it (checked
// with the kernel's peer credentials, which cannot be forged).

const (
	ServiceLabel   = "com.hopway.tun-service"
	ServiceSocket  = "/var/run/com.hopway.tun-service.sock"
	ServiceBinary  = "/Library/PrivilegedHelperTools/com.hopway.tun-service"
	ServicePlist   = "/Library/LaunchDaemons/com.hopway.tun-service.plist"
	ServiceVersion = 1 // bump when the request or reply changes
)

type serviceRequest struct {
	Version int  `json:"version"`
	IPv6    bool `json:"ipv6"`
}

type serviceReply struct {
	Version int    `json:"version"`
	Error   string `json:"error,omitempty"`
	Name    string `json:"name,omitempty"`
}

// RunService serves device requests on socketPath for allowedUID until the
// listener fails. create makes a device and returns its descriptor and name.
func RunService(socketPath string, allowedUID uint32, create func(Options) (int, string, error)) error {
	os.Remove(socketPath)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	// Grant access to the installing user. Verify peer credentials as well.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return err
	}
	if err := os.Chown(socketPath, int(allowedUID), -1); err != nil {
		return err
	}
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		// One request at a time. After a device is handed over the service
		// exits and launchd starts a fresh one, so no state from creating
		// devices accumulates in a long-running root process.
		if serveRequest(conn, allowedUID, create) {
			return nil
		}
	}
}

func serveRequest(conn *net.UnixConn, allowedUID uint32, create func(Options) (int, string, error)) bool {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	reply := serviceReply{Version: ServiceVersion}
	uid, err := peerUID(conn)
	var request serviceRequest
	switch {
	case err != nil:
		reply.Error = "cannot verify the caller: " + err.Error()
	case uid != allowedUID && uid != 0:
		reply.Error = fmt.Sprintf("user %d is not allowed to use this service", uid)
	default:
		decoder := json.NewDecoder(io.LimitReader(conn, 1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			reply.Error = "bad request"
		} else if request.Version != ServiceVersion {
			reply.Error = fmt.Sprintf("version mismatch (service %d, app %d): reinstall the service", ServiceVersion, request.Version)
		}
	}
	if reply.Error != "" {
		json.NewEncoder(conn).Encode(reply)
		return false
	}
	fd, name, err := create(Options{IPv6: request.IPv6})
	if err != nil {
		reply.Error = err.Error()
		json.NewEncoder(conn).Encode(reply)
		return false
	}
	reply.Name = name
	data, _ := json.Marshal(reply)
	conn.WriteMsgUnix(data, unixRights(fd), nil)
	closeFD(fd) // the caller now owns the device
	return true
}

// OpenWithService asks the installed service for a device.
func OpenWithService(ctx context.Context, socketPath string, ipv6 bool) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	unixConn := conn.(*net.UnixConn)
	writeErr := json.NewEncoder(conn).Encode(serviceRequest{Version: ServiceVersion, IPv6: ipv6})
	fd, data, err := receiveRights(unixConn) // read the answer even if the write failed
	defer func() {
		if fd > 0 {
			closeFD(fd)
		}
	}()
	if ctx.Err() != nil {
		return 0, "", ctx.Err()
	}
	if err != nil {
		if writeErr != nil {
			return 0, "", writeErr
		}
		return 0, "", err
	}
	var reply serviceReply
	reader := io.MultiReader(bytes.NewReader(data), conn)
	if err := json.NewDecoder(io.LimitReader(reader, 4096)).Decode(&reply); err != nil {
		if ctx.Err() != nil {
			return 0, "", ctx.Err()
		}
		return 0, "", fmt.Errorf("invalid reply from the TUN service: %w", err)
	}
	if reply.Version != ServiceVersion {
		return 0, "", errors.New("TUN service version mismatch: reinstall the service")
	}
	if reply.Error != "" {
		return 0, "", errors.New(reply.Error)
	}
	if fd <= 0 || reply.Name == "" {
		return 0, "", errors.New("the TUN service sent no device")
	}
	if ctx.Err() != nil {
		return 0, "", ctx.Err()
	}
	device := fd
	fd = 0
	return device, reply.Name, nil
}

// ServiceAvailable reports whether the service socket accepts connections.
func ServiceAvailable(socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// launchd job: KeepAlive restarts the service after each hand-off.
func servicePlist(binary string, uid uint32) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-tun-service</string>
		<string>%d</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ThrottleInterval</key><integer>1</integer>
</dict>
</plist>
`, ServiceLabel, binary, uid)
}

// InstallService runs as root (through the administrator prompt): it copies
// executable to a root-owned location, so the user cannot later swap the
// binary launchd runs as root, and registers the launchd job.
func InstallService(executable string, uid uint32) error {
	if os.Geteuid() != 0 {
		return errors.New("installing the TUN service needs root")
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	if err := os.MkdirAll("/Library/PrivilegedHelperTools", 0o755); err != nil {
		return err
	}
	tmp := ServiceBinary + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		return err
	}
	exec.Command("/bin/launchctl", "bootout", "system/"+ServiceLabel).Run()
	if err := os.Rename(tmp, ServiceBinary); err != nil {
		return err
	}
	if err := os.WriteFile(ServicePlist, []byte(servicePlist(ServiceBinary, uid)), 0o644); err != nil {
		return err
	}
	os.Chown(ServicePlist, 0, 0)
	if output, err := exec.Command("/bin/launchctl", "bootstrap", "system", ServicePlist).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

// UninstallService removes the launchd job and its files (as root).
func UninstallService() error {
	if os.Geteuid() != 0 {
		return errors.New("removing the TUN service needs root")
	}
	exec.Command("/bin/launchctl", "bootout", "system/"+ServiceLabel).Run()
	var errs []error
	for _, path := range []string{ServicePlist, ServiceBinary, ServiceSocket} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RunAsAdmin runs this executable with args through the administrator prompt.
func RunAsAdmin(ctx context.Context, executable, prompt string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	command := "quoted form of " + appleString(executable)
	for _, arg := range args {
		command += ` & " " & quoted form of ` + appleString(arg)
	}
	script := fmt.Sprintf(`do shell script %s with administrator privileges with prompt %s`, command, appleString(prompt))
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script)
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		message := strings.TrimSpace(string(output))
		if message == "" {
			return err
		}
		if strings.Contains(message, "-128") {
			message = "已取消授权"
		}
		return errors.New(message)
	}
	return nil
}
