// Package sysproxy points macOS's system proxy settings at HopWay and puts
// them back afterwards, even after a crash: the original settings of every
// network service are saved to disk before anything is changed, and a
// later start restores them if the previous run never did.
package sysproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Proxy is one of the three proxy slots of a network service.
type Proxy struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server,omitempty"`
	Port    int    `json:"port,omitempty"`
}

// Service is what HopWay changes on one network service.
type Service struct {
	Name   string   `json:"name"`
	Web    Proxy    `json:"web"`
	Secure Proxy    `json:"secure"`
	SOCKS  Proxy    `json:"socks"`
	Bypass []string `json:"bypass,omitempty"`
}

// Runner executes networksetup; tests replace it.
type Runner func(args ...string) (string, error)

func networksetup(args ...string) (string, error) {
	output, err := exec.Command("/usr/sbin/networksetup", args...).CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		if text == "" {
			text = err.Error()
		}
		return text, fmt.Errorf("networksetup %s: %s", args[0], text)
	}
	return text, nil
}

// DefaultBypass keeps local and private destinations off the proxy.
var DefaultBypass = []string{"127.0.0.1", "localhost", "*.local", "169.254/16", "10.0.0.0/8", "172.16.0.0/12",
	"192.168.0.0/16", "::1", "fe80::/10", "fc00::/7"}

type Manager struct {
	run    Runner
	backup string // path of the saved original settings
	mu     sync.Mutex
	active *Target
}

// Target is where the system proxy should point.
type Target struct {
	HTTP   string // host:port of HopWay's HTTP listener
	SOCKS  string // host:port of HopWay's SOCKS5 listener
	Bypass []string
}

func New(dataDir string, run Runner) *Manager {
	if run == nil {
		run = networksetup
	}
	return &Manager{run: run, backup: filepath.Join(dataDir, "system-proxy-backup.json")}
}

// Services lists enabled network services ("*" marks disabled ones).
func (m *Manager) Services() ([]string, error) {
	output, err := m.run("-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var services []string
	for i, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if i == 0 && strings.Contains(line, "asterisk") || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

func (m *Manager) read(service string) (Service, error) {
	result := Service{Name: service}
	for _, slot := range []struct {
		flag  string
		proxy *Proxy
	}{{"-getwebproxy", &result.Web}, {"-getsecurewebproxy", &result.Secure}, {"-getsocksfirewallproxy", &result.SOCKS}} {
		output, err := m.run(slot.flag, service)
		if err != nil {
			return result, err
		}
		*slot.proxy = parseProxy(output)
	}
	output, err := m.run("-getproxybypassdomains", service)
	if err != nil {
		return result, err
	}
	if !strings.Contains(output, "There aren't any") {
		for _, line := range strings.Split(output, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				result.Bypass = append(result.Bypass, line)
			}
		}
	}
	return result, nil
}

func parseProxy(output string) Proxy {
	var proxy Proxy
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Enabled":
			proxy.Enabled = value == "Yes"
		case "Server":
			proxy.Server = value
		case "Port":
			proxy.Port, _ = strconv.Atoi(value)
		}
	}
	return proxy
}

func (m *Manager) write(service Service) error {
	for _, slot := range []struct {
		set, state string
		proxy      Proxy
	}{
		{"-setwebproxy", "-setwebproxystate", service.Web},
		{"-setsecurewebproxy", "-setsecurewebproxystate", service.Secure},
		{"-setsocksfirewallproxy", "-setsocksfirewallproxystate", service.SOCKS},
	} {
		if slot.proxy.Server != "" && slot.proxy.Port > 0 {
			if _, err := m.run(slot.set, service.Name, slot.proxy.Server, strconv.Itoa(slot.proxy.Port)); err != nil {
				return err
			}
		}
		state := "off"
		if slot.proxy.Enabled {
			state = "on"
		}
		if _, err := m.run(slot.state, service.Name, state); err != nil {
			return err
		}
	}
	bypass := service.Bypass
	if len(bypass) == 0 {
		bypass = []string{"Empty"} // networksetup's keyword for "none"
	}
	_, err := m.run(append([]string{"-setproxybypassdomains", service.Name}, bypass...)...)
	return err
}

func (m *Manager) loadBackup() ([]Service, error) {
	data, err := os.ReadFile(m.backup)
	if err != nil {
		return nil, err
	}
	var services []Service
	if err := json.Unmarshal(data, &services); err != nil {
		return nil, err
	}
	return services, nil
}

func (m *Manager) saveBackup(services []Service) error {
	data, err := json.MarshalIndent(services, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.backup), 0o700); err != nil {
		return err
	}
	tmp := m.backup + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.backup)
}

func split(address string) (string, int, error) {
	host, port, ok := strings.Cut(address, ":")
	number, err := strconv.Atoi(port)
	if !ok || err != nil || number <= 0 {
		return "", 0, fmt.Errorf("invalid listener address %q", address)
	}
	return host, number, nil
}

// Enable points every enabled network service at HopWay. The original
// settings are saved first; a backup left by a crashed run is kept, because
// it holds the user's real settings rather than HopWay's.
func (m *Manager) Enable(target Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enableLocked(target)
}

func (m *Manager) enableLocked(target Target) error {
	httpHost, httpPort, err := split(target.HTTP)
	if err != nil {
		return err
	}
	socksHost, socksPort, err := split(target.SOCKS)
	if err != nil {
		return err
	}
	if len(target.Bypass) == 0 {
		target.Bypass = DefaultBypass
	}
	services, err := m.Services()
	if err != nil {
		return err
	}
	saved, _ := m.loadBackup()
	known := map[string]bool{}
	for _, service := range saved {
		known[service.Name] = true
	}
	for _, name := range services {
		if known[name] {
			continue
		}
		original, err := m.read(name)
		if err != nil {
			return err
		}
		saved = append(saved, original)
	}
	if err := m.saveBackup(saved); err != nil {
		return fmt.Errorf("save original proxy settings: %w", err)
	}
	for _, name := range services {
		service := Service{Name: name, Bypass: target.Bypass,
			Web:    Proxy{true, httpHost, httpPort},
			Secure: Proxy{true, httpHost, httpPort},
			SOCKS:  Proxy{true, socksHost, socksPort}}
		if err := m.write(service); err != nil {
			return err
		}
	}
	m.active = &target
	return nil
}

// Disable restores the saved settings and removes the backup.
func (m *Manager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = nil
	saved, err := m.loadBackup()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	current, _ := m.Services()
	present := map[string]bool{}
	for _, name := range current {
		present[name] = true
	}
	var failed []string
	for _, service := range saved {
		if current != nil && !present[service.Name] {
			continue // the service was removed meanwhile
		}
		if err := m.write(service); err != nil {
			failed = append(failed, err.Error())
		}
	}
	if len(failed) != 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return os.Remove(m.backup)
}

// Recover undoes a previous run that changed the settings and never put
// them back (crash, kill -9, power loss). Call it before Enable.
func (m *Manager) Recover() (bool, error) {
	if _, err := os.Stat(m.backup); err != nil {
		return false, nil
	}
	return true, m.Disable()
}

// Enabled reports whether HopWay currently owns the system proxy.
func (m *Manager) Enabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active != nil
}

// Refresh covers network services that appeared since Enable (a USB
// Ethernet dongle, a new Wi-Fi adapter). Services the user changed by hand
// are left alone: HopWay never fights the user over the setting.
func (m *Manager) Refresh() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return false, nil
	}
	services, err := m.Services()
	if err != nil {
		return false, err
	}
	saved, _ := m.loadBackup()
	known := map[string]bool{}
	for _, service := range saved {
		known[service.Name] = true
	}
	for _, name := range services {
		if !known[name] {
			return true, m.enableLocked(*m.active)
		}
	}
	return false, nil
}
