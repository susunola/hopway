//go:build linux && !hopway_native

package tun

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServiceHandsOverOnlyToTheInstallingUser(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "svc.sock")
	file, _ := os.CreateTemp(t.TempDir(), "device")
	file.WriteString("device")
	created := 0
	create := func(options Options) (int, string, error) {
		created++
		fd, err := unix.Dup(int(file.Fd()))
		return fd, "utun9", err
	}
	// The caller is uid 0 here (root may always ask); a stranger uid is refused.
	done := make(chan error, 1)
	go func() { done <- RunService(socket, uint32(os.Geteuid()), create) }()
	for !ServiceAvailable(socket) {
	}
	fd, name, err := OpenWithService(context.Background(), socket, Options{})
	if err != nil || name != "utun9" || created != 1 {
		t.Fatalf("open: %d %q %v", fd, name, err)
	}
	buffer := make([]byte, 6)
	if n, _ := unix.Pread(fd, buffer, 0); string(buffer[:n]) != "device" {
		t.Fatal("received descriptor does not refer to the device")
	}
	unix.Close(fd)
	if err := <-done; err != nil {
		t.Fatalf("service must exit after a hand-off: %v", err)
	}
	if info, err := os.Stat(socket); err == nil && info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", info.Mode())
	}
}

func TestServiceRejectsOtherUsersAndVersions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run a client as another user")
	}
	dir, _ := os.MkdirTemp("", "hopway-svc-")
	defer os.RemoveAll(dir)
	os.Chmod(dir, 0o755)
	socket := filepath.Join(dir, "svc.sock")
	go RunService(socket, 4242, func(Options) (int, string, error) { t.Fatal("must not create"); return 0, "", nil })
	for !ServiceAvailable(socket) {
	}
	// A client running as another user is refused by the kernel-checked uid.
	self, _ := os.ReadFile(os.Args[0])
	binary := filepath.Join(dir, "client.test")
	os.WriteFile(binary, self, 0o755)
	client := exec.Command(binary, "-test.run=TestServiceClientHelper", "-test.v")
	client.Dir = dir
	client.Env = append(os.Environ(), "HOPWAY_SERVICE_CLIENT="+socket)
	client.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 4243, Gid: 4243}}
	output, _ := client.CombinedOutput()
	if !strings.Contains(string(output), "permission denied") {
		t.Fatalf("stranger was not refused: %s", output)
	}
	// A request with the wrong version is refused before anything is created.
	conn, err := dialRaw(socket)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte(`{"version":999}` + "\n"))
	data := make([]byte, 512)
	n, _ := conn.Read(data)
	if !strings.Contains(string(data[:n]), "version mismatch") {
		t.Fatalf("reply %s", data[:n])
	}
}

// TestServiceClientHelper is the client half of the uid test, run as a
// child process under another uid.
func TestServiceClientHelper(t *testing.T) {
	socket := os.Getenv("HOPWAY_SERVICE_CLIENT")
	if socket == "" {
		t.Skip("helper process only")
	}
	_, _, err := OpenWithService(context.Background(), socket, Options{})
	fmt.Println("client result:", err)
}

func TestServicePlist(t *testing.T) {
	plist := servicePlist(ServiceBinary, 501)
	for _, want := range []string{ServiceLabel, ServiceBinary, "-tun-service", "<string>501</string>", "<key>KeepAlive</key><true/>"} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %s", want)
		}
	}
}
