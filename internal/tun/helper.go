//go:build !hopway_native && (darwin || linux)

package tun

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"mac-proxy/internal/wire"

	stun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
)

// RunHelper is the privileged half of TUN mode. Running as root, it creates
// the device and its routes, hands the descriptor to the unprivileged core
// and exits without closing it: the device (and the routes, which belong to
// it) lives exactly as long as the core keeps the descriptor open.
func RunHelper(socketPath string, options Options) error {
	fd, name, err := CreateDevice(options)
	if err != nil {
		return err
	}
	return SendDevice(socketPath, fd, name)
}

// CreateDevice makes a TUN device with routes (root only) and returns its
// descriptor without closing it: the device and its routes then live as
// long as whoever receives the descriptor keeps it open.
func CreateDevice(options Options) (int, string, error) {
	if os.Geteuid() != 0 {
		return 0, "", errors.New("creating the TUN device needs root")
	}
	if err := wire.ValidateTUNMTU(options.MTU, options.IPv6); err != nil {
		return 0, "", err
	}
	options.defaults()
	if err := options.CheckFakeIPNetworks(); err != nil {
		return 0, "", err
	}
	finder := control.NewDefaultInterfaceFinder()
	network, err := stun.NewNetworkUpdateMonitor(logger.NOP())
	if err != nil {
		return 0, "", err
	}
	monitor, err := stun.NewDefaultInterfaceMonitor(network, logger.NOP(), stun.DefaultInterfaceMonitorOptions{InterfaceFinder: finder})
	if err != nil {
		return 0, "", err
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
		return 0, "", err
	}
	if err := device.Start(); err != nil {
		device.Close()
		return 0, "", err
	}
	fd, err := deviceFD(device)
	if err != nil {
		device.Close()
		return 0, "", err
	}
	return fd, name, nil
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
func OpenWithHelper(ctx context.Context, executable string, options Options) (int, string, error) {
	if runtime.GOOS != "darwin" {
		return 0, "", errors.New("the TUN helper is only used on macOS")
	}
	path, listener, cleanup, err := helperSocket()
	if err != nil {
		return 0, "", err
	}
	defer cleanup()
	flags := ""
	if options.IPv6 {
		flags += " -tun-ipv6"
	}
	if options.MTU != 0 && options.MTU != DefaultMTU {
		flags += " -tun-mtu " + strconv.FormatUint(uint64(options.MTU), 10)
	}
	flags += " -tun-helper "
	script := fmt.Sprintf(`do shell script quoted form of %s & "`+flags+`" & quoted form of %s with administrator privileges with prompt "HopWay 需要管理员权限来开启增强模式（TUN），用于创建虚拟网卡并接管路由。"`,
		appleString(executable), appleString(path))
	ctx, stop := context.WithTimeout(ctx, 2*time.Minute)
	defer stop()
	ctx, fail := context.WithCancelCause(ctx)
	defer fail(nil)
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script)
	cmd.WaitDelay = time.Second
	var output strings.Builder
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return 0, "", err
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			message := strings.TrimSpace(output.String())
			if strings.Contains(message, "-128") {
				message = "已取消授权"
			}
			if message != "" {
				err = errors.New(message)
			}
			fail(err)
		}
	}()
	return receiveDevice(ctx, listener, true)
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
