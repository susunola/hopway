// Package sysproxy points macOS's system proxy settings at HopWay and puts
// them back afterwards, even after a crash: the original settings of every
// network service are saved to disk before anything is changed, and a
// later start restores them if the previous run never did.
package sysproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Proxy is one of the three proxy slots of a network service.
type Proxy struct {
	Enabled       bool   `json:"enabled"`
	Server        string `json:"server,omitempty"`
	Port          int    `json:"port,omitempty"`
	Authenticated bool   `json:"authenticated,omitempty"`
}

// Service is what HopWay changes on one network service.
type Service struct {
	Name       string   `json:"name"`
	Web        Proxy    `json:"web"`
	Secure     Proxy    `json:"secure"`
	SOCKS      Proxy    `json:"socks"`
	Bypass     []string `json:"bypass,omitempty"`
	Applied    *Service `json:"applied,omitempty"`    // present only in the recovery journal
	RestoreOff uint8    `json:"restoreOff,omitempty"` // slots that may need switching off after an interrupted restore
}

// Runner executes networksetup; tests replace it.
type Runner func(args ...string) (string, error)

func networksetup(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/sbin/networksetup", args...).CombinedOutput()
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
	active atomic.Pointer[Target]
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
	return m.services(false)
}

func (m *Manager) services(includeDisabled bool) ([]string, error) {
	output, err := m.run("-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var services []string
	for i, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if i == 0 && strings.Contains(line, "asterisk") || line == "" {
			continue
		}
		if name, disabled := strings.CutPrefix(line, "*"); disabled {
			if !includeDisabled {
				continue
			}
			line = strings.TrimSpace(name)
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
		case "Authenticated Proxy Enabled":
			proxy.Authenticated = value == "1" || value == "Yes"
		}
	}
	return proxy
}

// write applies desired settings. During recovery it only touches fields
// still pointing at HopWay, including a slot whose address was written before
// the process could set its enabled state.
func (m *Manager) write(service Service, current *Service) error {
	slots := []struct {
		set, state string
		proxy      Proxy
	}{
		{"-setwebproxy", "-setwebproxystate", service.Web},
		{"-setsecurewebproxy", "-setsecurewebproxystate", service.Secure},
		{"-setsocksfirewallproxy", "-setsocksfirewallproxystate", service.SOCKS},
	}
	var currentSlots, appliedSlots [3]Proxy
	if current != nil {
		currentSlots = [3]Proxy{current.Web, current.Secure, current.SOCKS}
		appliedSlots = [3]Proxy{service.Applied.Web, service.Applied.Secure, service.Applied.SOCKS}
	}
	var failures []error
	for i, slot := range slots {
		if current != nil {
			now, applied := currentSlots[i], appliedSlots[i]
			if now.Authenticated {
				continue
			}
			if now.Server != applied.Server || now.Port != applied.Port {
				if service.RestoreOff&(1<<i) != 0 && now.Enabled &&
					now.Server == slot.proxy.Server && now.Port == slot.proxy.Port {
					_, err := m.run(slot.state, service.Name, "off")
					failures = append(failures, err)
				}
				continue
			}
			// Preserve a manual switch-off while restoring the address.
			slot.proxy.Enabled = slot.proxy.Enabled && now.Enabled && service.RestoreOff&(1<<i) == 0
		}
		err := m.writeSlot(service.Name, slot.set, slot.state, slot.proxy)
		if err != nil {
			if current == nil {
				return err
			}
			failures = append(failures, err)
		}
	}
	if current == nil || slices.Equal(current.Bypass, service.Applied.Bypass) {
		bypass := service.Bypass
		if len(bypass) == 0 {
			bypass = []string{"Empty"}
		}
		_, err := m.run(append([]string{"-setproxybypassdomains", service.Name}, bypass...)...)
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (m *Manager) writeSlot(name, set, state string, proxy Proxy) error {
	if proxy.Server != "" && proxy.Port > 0 {
		if _, err := m.run(set, name, proxy.Server, strconv.Itoa(proxy.Port)); err != nil {
			return err
		}
	}
	value := "off"
	if proxy.Enabled {
		value = "on"
	}
	_, err := m.run(state, name, value)
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

func writeBackup(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".network-backup-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	if err := errors.Join(writeErr, syncErr, file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func split(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return "", 0, fmt.Errorf("invalid listener address %q", address)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number <= 0 || number > 65535 {
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
	_, err := m.enableLocked(target)
	return err
}

func (m *Manager) enableLocked(target Target) (bool, error) {
	httpHost, httpPort, err := split(target.HTTP)
	if err != nil {
		return false, err
	}
	socksHost, socksPort, err := split(target.SOCKS)
	if err != nil {
		return false, err
	}
	if len(target.Bypass) == 0 {
		target.Bypass = DefaultBypass
	}
	services, err := m.Services()
	if err != nil {
		return false, err
	}
	if len(services) == 0 {
		return false, errors.New("no enabled network service")
	}
	saved, err := m.loadBackup()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read original proxy settings: %w", err)
	}
	if len(saved) > 0 && m.active.Load() == nil {
		return false, errors.New("restore the previous proxy settings before enabling the system proxy")
	}
	known := map[string]Service{}
	for _, service := range saved {
		known[service.Name] = service
	}
	var added []Service
	for _, name := range services {
		applied := Service{Name: name, Bypass: slices.Clone(target.Bypass),
			Web:    Proxy{Enabled: true, Server: httpHost, Port: httpPort},
			Secure: Proxy{Enabled: true, Server: httpHost, Port: httpPort},
			SOCKS:  Proxy{Enabled: true, Server: socksHost, Port: socksPort}}
		if entry, ok := known[name]; ok {
			prior := entry.Applied
			if prior == nil || prior.Web != applied.Web || prior.Secure != applied.Secure ||
				prior.SOCKS != applied.SOCKS || !slices.Equal(prior.Bypass, applied.Bypass) {
				return false, errors.New("restore the previous proxy settings before changing the target")
			}
			continue
		}
		original, err := m.read(name)
		if err != nil {
			return false, err
		}
		if original.Web.Authenticated || original.Secure.Authenticated || original.SOCKS.Authenticated {
			return false, fmt.Errorf("cannot safely replace the authenticated proxy on %s", name)
		}
		original.Applied = &applied
		added = append(added, original)
	}
	if len(added) > 0 {
		if err := writeBackup(m.backup, append(saved, added...)); err != nil {
			return false, fmt.Errorf("save original proxy settings: %w", err)
		}
		for _, service := range added {
			if err := m.write(*service.Applied, nil); err != nil {
				return false, errors.Join(err, m.rollback(saved, added))
			}
		}
	}
	m.active.Store(&target)
	return len(added) > 0, nil
}

// rollback reverses only the newly added services. Previously owned services
// stay active if a refresh fails. Keep the full journal if reversal failed.
func (m *Manager) rollback(saved, added []Service) error {
	if err := m.restore(append(saved, added...), len(saved)); err != nil {
		return err
	}
	if len(saved) == 0 {
		return os.Remove(m.backup)
	}
	return writeBackup(m.backup, saved)
}

// restore persists intent before issuing any restore command that could
// temporarily re-enable a proxy at its original address. That address then
// remains recognizable if the process exits between the two commands.
func (m *Manager) restore(saved []Service, from int) error {
	current, err := m.services(true)
	if err != nil {
		return err
	}
	states := make(map[string]Service, len(saved)-from)
	var failures []error
	dirty := false
	for i := from; i < len(saved); i++ {
		service := &saved[i]
		if service.Applied == nil || !slices.Contains(current, service.Name) {
			continue
		}
		actual, err := m.read(service.Name)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		states[service.Name] = actual
		before := service.RestoreOff
		originals := [...]Proxy{service.Web, service.Secure, service.SOCKS}
		owned := [...]Proxy{service.Applied.Web, service.Applied.Secure, service.Applied.SOCKS}
		for j, now := range [...]Proxy{actual.Web, actual.Secure, actual.SOCKS} {
			old, applied := originals[j], owned[j]
			if !now.Authenticated && now.Server == applied.Server && now.Port == applied.Port &&
				old.Server != "" && old.Port > 0 && (!old.Enabled || !now.Enabled) {
				service.RestoreOff |= 1 << j
			}
		}
		dirty = dirty || before != service.RestoreOff
	}
	if dirty {
		if err := writeBackup(m.backup, saved); err != nil {
			return errors.Join(errors.Join(failures...), err)
		}
	}
	for _, service := range saved[from:] {
		if !slices.Contains(current, service.Name) {
			continue
		}
		var state *Service
		if service.Applied != nil {
			actual, ok := states[service.Name]
			if !ok {
				continue
			}
			state = &actual
		}
		failures = append(failures, m.write(service, state))
	}
	return errors.Join(failures...)
}

// Disable restores the saved settings and removes the backup.
func (m *Manager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	saved, err := m.loadBackup()
	if errors.Is(err, os.ErrNotExist) {
		m.active.Store(nil)
		return nil
	}
	if err != nil {
		return err
	}
	if err := m.restore(saved, 0); err != nil {
		return err
	}
	m.active.Store(nil)
	return os.Remove(m.backup)
}

// Recover undoes a previous run that changed the settings and never put them
// back. Call it before Enable.
func (m *Manager) Recover() (bool, error) {
	_, proxyErr := os.Stat(m.backup)
	_, dnsErr := os.Stat(m.dnsBackupPath())
	if errors.Is(proxyErr, os.ErrNotExist) && errors.Is(dnsErr, os.ErrNotExist) {
		return false, nil
	}
	err := errors.Join(m.Disable(), m.RestoreDNS())
	return err == nil, err
}

// Enabled reports whether HopWay currently owns the system proxy.
func (m *Manager) Enabled() bool {
	return m.active.Load() != nil
}

// Refresh adds only new services, leaving settings on existing services alone.
func (m *Manager) Refresh() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if target := m.active.Load(); target != nil {
		return m.enableLocked(*target)
	}
	return false, nil
}
