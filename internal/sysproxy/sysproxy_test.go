package sysproxy

import (
	"fmt"
	"os"
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
		auth := 0
		if p.Authenticated {
			auth = 1
		}
		return fmt.Sprintf("Enabled: %s\nServer: %s\nPort: %d\nAuthenticated Proxy Enabled: %d", enabled, p.Server, p.Port, auth), nil
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
		p.Enabled = true // networksetup's set commands also enable the slot
	}
	return "", nil
}

var target = Target{HTTP: "127.0.0.1:8080", SOCKS: "127.0.0.1:1080"}

func TestEnableDisableRestoresOriginal(t *testing.T) {
	f := newFake("Wi-Fi", "USB 10/100/1000 LAN")
	f.state["Wi-Fi"].Web = Proxy{Enabled: true, Server: "corp-proxy.test", Port: 3128}
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
	if wifi.Web != (Proxy{Enabled: true, Server: "corp-proxy.test", Port: 3128}) || wifi.SOCKS.Enabled || len(wifi.Bypass) != 1 || wifi.Bypass[0] != "*.corp.test" {
		t.Fatalf("original not restored: %+v", wifi)
	}
	if lan := f.state["USB 10/100/1000 LAN"]; lan.Web.Enabled || lan.Secure.Enabled || len(lan.Bypass) != 0 {
		t.Fatalf("second service not restored: %+v", lan)
	}
}

func TestRecoverAfterCrash(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi")
	f.state["Wi-Fi"].Secure = Proxy{Enabled: true, Server: "orig.test", Port: 443}
	crashed := New(dir, f.run)
	if err := crashed.Enable(target); err != nil {
		t.Fatal(err)
	}
	// The process dies here. A second Enable in the next run must not save
	// HopWay's own settings as the "original".
	next := New(dir, f.run)
	if err := next.Enable(target); err == nil {
		t.Fatal("takeover must wait until the pending recovery completes")
	}
	if err := next.Disable(); err != nil {
		t.Fatal(err)
	}
	if f.state["Wi-Fi"].Secure != (Proxy{Enabled: true, Server: "orig.test", Port: 443}) || f.state["Wi-Fi"].Web.Enabled {
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
	if f.state["Wi-Fi"].Web.Enabled {
		t.Fatal("adding Ethernet re-enabled a manually disabled Wi-Fi proxy")
	}
	m.Disable()
	if f.state["Thunderbolt Ethernet"].Web.Enabled {
		t.Fatal("new service not restored")
	}
}

func TestEnableFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi")
	f.state["Wi-Fi"].Web = Proxy{Enabled: true, Server: "orig.test", Port: 1}
	f.failOn = "-setsecurewebproxy"
	m := New(dir, f.run)
	if err := m.Enable(target); err == nil {
		t.Fatal("expected failure")
	}
	if m.Enabled() || f.state["Wi-Fi"].Web.Server != "orig.test" {
		t.Fatalf("rollback did not restore the web proxy: %+v", f.state["Wi-Fi"])
	}
	if _, err := os.Stat(m.backup); !os.IsNotExist(err) {
		t.Fatalf("successful rollback should remove the journal: %v", err)
	}
}

func TestDNSOverrideAndRecover(t *testing.T) {
	dir := t.TempDir()
	dnsState := map[string][]string{"Wi-Fi": {"192.168.1.1"}}
	f := newFake("Wi-Fi", "Ethernet")
	run := func(args ...string) (string, error) {
		switch args[0] {
		case "-getdnsservers":
			if len(dnsState[args[1]]) == 0 {
				return "There aren't any DNS Servers set on " + args[1] + ".", nil
			}
			return strings.Join(dnsState[args[1]], "\n"), nil
		case "-setdnsservers":
			dnsState[args[1]] = nil
			if args[2] != "Empty" {
				dnsState[args[1]] = args[2:]
			}
			return "", nil
		}
		return f.run(args...)
	}
	m := New(dir, run)
	if err := m.SetDNS("172.19.0.2"); err != nil {
		t.Fatal(err)
	}
	if dnsState["Wi-Fi"][0] != "172.19.0.2" || dnsState["Ethernet"][0] != "172.19.0.2" {
		t.Fatalf("not applied: %v", dnsState)
	}
	// Crash, then the next start recovers.
	if restored, err := New(dir, run).Recover(); !restored || err != nil {
		t.Fatalf("recover: %v %v", restored, err)
	}
	if len(dnsState["Wi-Fi"]) != 1 || dnsState["Wi-Fi"][0] != "192.168.1.1" || len(dnsState["Ethernet"]) != 0 {
		t.Fatalf("not restored: %v", dnsState)
	}
}

func TestRestorePreservesExternalChanges(t *testing.T) {
	f := newFake("Wi-Fi")
	wifi := f.state["Wi-Fi"]
	wifi.Secure = Proxy{Enabled: true, Server: "original.test", Port: 3128}
	m := New(t.TempDir(), f.run)
	if err := m.Enable(target); err != nil {
		t.Fatal(err)
	}
	wifi.Web = Proxy{Enabled: true, Server: "manual.test", Port: 8000}
	wifi.Secure.Enabled = false
	wifi.Bypass = []string{"*.manual.test"}
	if err := m.Disable(); err != nil {
		t.Fatal(err)
	}
	if wifi.Web.Server != "manual.test" || wifi.Secure.Enabled || wifi.Secure.Server != "original.test" ||
		wifi.SOCKS.Enabled || len(wifi.Bypass) != 1 || wifi.Bypass[0] != "*.manual.test" {
		t.Fatalf("unexpected recovery state: %+v", wifi)
	}
}

func TestEnableKeepsUnreadableJournalAndAuthenticatedProxy(t *testing.T) {
	f := newFake("Wi-Fi")
	m := New(t.TempDir(), f.run)
	if err := os.WriteFile(m.backup, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Enable(target); err == nil {
		t.Fatal("accepted corrupt journal")
	}
	if data, err := os.ReadFile(m.backup); err != nil || string(data) != "{bad" {
		t.Fatalf("journal changed: %q %v", data, err)
	}
	if err := os.Remove(m.backup); err != nil {
		t.Fatal(err)
	}
	f.state["Wi-Fi"].Web = Proxy{Enabled: true, Server: "corp.test", Port: 3128, Authenticated: true}
	if err := m.Enable(target); err == nil || f.state["Wi-Fi"].Web.Server != "corp.test" {
		t.Fatalf("authenticated proxy was not preserved: %v", err)
	}
}

func TestRecoveryRetriesSwitchOffAfterInterruptedRestore(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi")
	wifi := f.state["Wi-Fi"]
	wifi.Web = Proxy{Server: "original.test", Port: 3128}
	m := New(dir, f.run)
	if err := m.Enable(target); err != nil {
		t.Fatal(err)
	}
	f.failOn = "-setwebproxystate"
	if err := m.Disable(); err == nil || !wifi.Web.Enabled || wifi.Web.Server != "original.test" {
		t.Fatalf("expected interruption after restoring the address, got %+v, %v", wifi.Web, err)
	}
	f.failOn = ""
	if restored, err := New(dir, f.run).Recover(); !restored || err != nil || wifi.Web.Enabled {
		t.Fatalf("could not finish restoring the disabled proxy: %+v, %v", wifi.Web, err)
	}
}

func TestDNSRollbackAndManualChange(t *testing.T) {
	f := newFake("Wi-Fi", "Ethernet")
	current := map[string]string{"Wi-Fi": "192.0.2.53"}
	refuseEthernet := true
	run := func(args ...string) (string, error) {
		switch args[0] {
		case "-getdnsservers":
			if current[args[1]] == "" {
				return "There aren't any DNS Servers set.", nil
			}
			return current[args[1]], nil
		case "-setdnsservers":
			if refuseEthernet && args[1] == "Ethernet" {
				return "", fmt.Errorf("access denied")
			}
			if args[2] == "Empty" {
				delete(current, args[1])
			} else {
				current[args[1]] = args[2]
			}
			return "", nil
		}
		return f.run(args...)
	}
	dir := t.TempDir()
	m := New(dir, run)
	if err := m.SetDNS("172.19.0.2"); err == nil || current["Wi-Fi"] != "192.0.2.53" {
		t.Fatalf("first service not rolled back: %v %v", current, err)
	}
	refuseEthernet = false
	if err := m.SetDNS("172.19.0.2"); err != nil {
		t.Fatal(err)
	}
	current["Wi-Fi"] = "198.51.100.53" // another app or the user changed DNS
	if recovered, err := New(dir, run).Recover(); !recovered || err != nil {
		t.Fatalf("recover DNS: %v %v", recovered, err)
	}
	if current["Wi-Fi"] != "198.51.100.53" || current["Ethernet"] != "" {
		t.Fatalf("recovery overwrote an external change or failed to clear Ethernet DNS: %v", current)
	}
}
