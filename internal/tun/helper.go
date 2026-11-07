//go:build !hopway_native && (darwin || linux)

package tun

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"time"

	stun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
)

// RunHelper is the privileged half of TUN mode. Running as root, it creates
// the device and its routes, hands the descriptor to the unprivileged core
// and exits without closing it: the device (and the routes, which belong to
// it) lives exactly as long as the core keeps the descriptor open.
func RunHelper(socketPath string, options Options) error {
	if os.Geteuid() != 0 {
		return errors.New("the TUN helper must run as root")
	}
	options.defaults()
	finder := control.NewDefaultInterfaceFinder()
	network, err := stun.NewNetworkUpdateMonitor(logger.NOP())
	if err != nil {
		return err
	}
	monitor, err := stun.NewDefaultInterfaceMonitor(network, logger.NOP(), stun.DefaultInterfaceMonitorOptions{InterfaceFinder: finder})
	if err != nil {
		return err
	}
	network.Start()
	monitor.Start()
	name := options.Name
	if name == "" {
		name = stun.CalculateInterfaceName("")
	}
	tunOptions := stun.Options{Name: name, Inet4Address: []netip.Prefix{options.Address}, MTU: options.MTU,
		AutoRoute: true, InterfaceMonitor: monitor, InterfaceFinder: finder}
	if options.IPv6 {
		tunOptions.Inet6Address = []netip.Prefix{defaultAddress6}
	}
	device, err := stun.New(tunOptions)
	if err != nil {
		return err
	}
	if err := device.Start(); err != nil {
		device.Close()
		return err
	}
	fd, err := deviceFD(device)
	if err != nil {
		device.Close()
		return err
	}
	if err := SendDevice(socketPath, fd, name); err != nil {
		device.Close()
		return err
	}
	return nil
}

// deviceFD reads the descriptor sing-tun keeps for the device.
func deviceFD(device stun.Tun) (int, error) {
	value := reflect.ValueOf(device)
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.Kind() == reflect.Struct {
		if field := value.FieldByName("tunFd"); field.IsValid() && field.CanInt() {
			return int(field.Int()), nil
		}
		if field := value.FieldByName("tunFile"); field.IsValid() && !field.IsNil() {
			if file, ok := reflect.NewAt(field.Type(), field.Addr().UnsafePointer()).Elem().Interface().(*os.File); ok {
				return int(file.Fd()), nil
			}
		}
	}
	return 0, fmt.Errorf("cannot get the device descriptor from %T", device)
}

// OpenWithHelper asks for administrator rights (macOS's standard password
// dialog) to run executable as the helper, and returns the device it sends.
func OpenWithHelper(executable string, ipv6 bool) (int, string, error) {
	if runtime.GOOS != "darwin" {
		return 0, "", errors.New("the TUN helper is only used on macOS")
	}
	path, listener, cleanup, err := helperSocket()
	if err != nil {
		return 0, "", err
	}
	defer cleanup()
	flags := " -tun-helper "
	if ipv6 {
		flags = " -tun-ipv6 -tun-helper "
	}
	script := fmt.Sprintf(`do shell script quoted form of %s & "`+flags+`" & quoted form of %s with administrator privileges with prompt "HopWay 需要管理员权限来开启增强模式（TUN），用于创建虚拟网卡并接管路由。"`,
		appleString(executable), appleString(path))
	cmd := exec.Command("/usr/bin/osascript", "-e", script)
	var output strings.Builder
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return 0, "", err
	}
	exited := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		if err != nil {
			message := strings.TrimSpace(output.String())
			if strings.Contains(message, "-128") {
				message = "已取消授权"
			}
			err = errors.New(message)
		}
		exited <- err
	}()
	abort := make(chan error, 1)
	go func() {
		if err := <-exited; err != nil {
			abort <- err
		}
	}()
	return ReceiveDevice(listener, 2*time.Minute, abort)
}

// appleString quotes s as an AppleScript string literal.
func appleString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// SystemDNS lists the configured DNS servers (host:port) from resolv.conf,
// read before the system DNS is pointed at the tunnel.
func SystemDNS(exclude netip.Addr) []string {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer file.Close()
	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			addr, err := netip.ParseAddr(fields[1])
			if err != nil || addr == exclude || addr.IsLoopback() {
				continue
			}
			servers = append(servers, netip.AddrPortFrom(addr, 53).String())
		}
	}
	return servers
}
