package sysproxy

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// fake simulates networksetup's state and output format.
type fake struct {
	services []string
	state    map[string]*Service
	calls    int
	failOn   string
}

func newFake(services ...string) *fake {
	f := &fake{services: services, state: map[string]*Service{}}
	for _, name := range services {
		f.state[name] = &Service{Name: name}
	}
	return f
}

func (f *fake) run(args ...string) (string, error) {
	f.calls++
	if f.failOn != "" && args[0] == f.failOn {
		return "", fmt.Errorf("networksetup %s: denied", args[0])
	}
	if args[0] == "-listallnetworkservices" {
		return "An asterisk (*) denotes that a network service is disabled.\n" + strings.Join(f.services, "\n") + "\n*Disabled VPN", nil
	}
	service := f.state[args[1]]
	if service == nil {
		f.state[args[1]] = &Service{Name: args[1]}
		service = f.state[args[1]]
	}
	slot := map[string]*Proxy{"web": &service.Web, "secure": &service.Secure, "socks": &service.SOCKS}
	name := func(flag string) string {
		switch {
		case strings.Contains(flag, "secureweb"):
			return "secure"
		case strings.Contains(flag, "socks"):
			return "socks"
		}
		return "web"
	}
	switch {
	case strings.HasPrefix(args[0], "-get") && strings.Contains(args[0], "bypass"):
		if len(service.Bypass) == 0 {
			return "There aren't any bypass domains set on " + args[1] + ".", nil
		}
		return strings.Join(service.Bypass, "\n"), nil
	case strings.HasPrefix(args[0], "-get"):
		p := slot[name(args[0])]
		enabled := "No"
		if p.Enabled {
			enabled = "Yes"
		}
		return fmt.Sprintf("Enabled: %s\nServer: %s\nPort: %d\nAuthenticated Proxy Enabled: 0", enabled, p.Server, p.Port), nil
	case strings.Contains(args[0], "bypass"):
		service.Bypass = nil
		if args[2] != "Empty" {
			service.Bypass = append([]string(nil), args[2:]...)
		}
	case strings.HasSuffix(args[0], "state"):
		slot[name(args[0])].Enabled = args[2] == "on"
	default:
		p := slot[name(args[0])]
		p.Server = args[2]
		p.Port, _ = strconv.Atoi(args[3])
	}
	return "", nil
}

var target = Target{HTTP: "127.0.0.1:8080", SOCKS: "127.0.0.1:1080"}

func TestEnableDisableRestoresOriginal(t *testing.T) {
	f := newFake("Wi-Fi", "USB 10/100/1000 LAN")
	f.state["Wi-Fi"].Web = Proxy{true, "corp-proxy.test", 3128}
	f.state["Wi-Fi"].Bypass = []string{"*.corp.test"}
	m := New(t.TempDir(), f.run)
	if err := m.Enable(target); err != nil {
		t.Fatal(err)
	}
	wifi := f.state["Wi-Fi"]
	if !wifi.Web.Enabled || wifi.Web.Port != 8080 || !wifi.SOCKS.Enabled || wifi.SOCKS.Port != 1080 || wifi.Bypass[0] != "127.0.0.1" {
		t.Fatalf("not applied: %+v", wifi)
	}
	if _, ok := f.state["*Disabled VPN"]; ok {
		t.Fatal("touched a disabled service")
	}
	if err := m.Disable(); err != nil {
		t.Fatal(err)
	}
	if wifi.Web != (Proxy{true, "corp-proxy.test", 3128}) || wifi.SOCKS.Enabled || len(wifi.Bypass) != 1 || wifi.Bypass[0] != "*.corp.test" {
		t.Fatalf("original not restored: %+v", wifi)
	}
	if lan := f.state["USB 10/100/1000 LAN"]; lan.Web.Enabled || lan.Secure.Enabled || len(lan.Bypass) != 0 {
		t.Fatalf("second service not restored: %+v", lan)
	}
}

func TestRecoverAfterCrash(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi")
	f.state["Wi-Fi"].Secure = Proxy{true, "orig.test", 443}
	crashed := New(dir, f.run)
	if err := crashed.Enable(target); err != nil {
		t.Fatal(err)
	}
	// The process dies here. A second Enable in the next run must not save
	// HopWay's own settings as the "original".
	next := New(dir, f.run)
	if err := next.Enable(target); err != nil {
		t.Fatal(err)
	}
	if err := next.Disable(); err != nil {
		t.Fatal(err)
	}
	if f.state["Wi-Fi"].Secure != (Proxy{true, "orig.test", 443}) || f.state["Wi-Fi"].Web.Enabled {
		t.Fatalf("crash recovery lost the user's settings: %+v", f.state["Wi-Fi"])
	}

	// Recover alone also restores.
	again := New(dir, f.run)
	again.Enable(target)
	fresh := New(dir, f.run)
	if restored, err := fresh.Recover(); !restored || err != nil || f.state["Wi-Fi"].Web.Enabled {
		t.Fatalf("recover: %v %v %+v", restored, err, f.state["Wi-Fi"])
	}
	if restored, _ := fresh.Recover(); restored {
		t.Fatal("nothing left to recover")
	}
}

func TestRefreshCoversNewServicesOnly(t *testing.T) {
	f := newFake("Wi-Fi")
	m := New(t.TempDir(), f.run)
	m.Enable(target)
	f.state["Wi-Fi"].Web.Enabled = false // the user turned it off by hand
	if changed, err := m.Refresh(); changed || err != nil || f.state["Wi-Fi"].Web.Enabled {
		t.Fatal("refresh must not override the user's own change")
	}
	f.services = append(f.services, "Thunderbolt Ethernet")
	if changed, err := m.Refresh(); !changed || err != nil || !f.state["Thunderbolt Ethernet"].Web.Enabled {
		t.Fatalf("new service not covered: %v %v", changed, err)
	}
	m.Disable()
	if f.state["Thunderbolt Ethernet"].Web.Enabled {
		t.Fatal("new service not restored")
	}
}

func TestEnableFailureLeavesBackup(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi")
	f.state["Wi-Fi"].Web = Proxy{true, "orig.test", 1}
	f.failOn = "-setsecurewebproxy"
	m := New(dir, f.run)
	if err := m.Enable(target); err == nil {
		t.Fatal("expected failure")
	}
	f.failOn = ""
	// Even a half-applied change can be undone.
	if restored, err := New(dir, f.run).Recover(); !restored || err != nil || f.state["Wi-Fi"].Web.Server != "orig.test" {
		t.Fatalf("restore after partial enable: %v %v %+v", restored, err, f.state["Wi-Fi"])
	}
}
