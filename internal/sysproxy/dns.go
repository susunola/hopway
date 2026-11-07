package sysproxy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// DNS settings are changed in TUN mode so that queries to a DNS server on
// the local network (which has its own route and would bypass the tunnel)
// reach HopWay. They are backed up and restored like the proxy settings.

type dnsBackup struct {
	Service string   `json:"service"`
	Servers []string `json:"servers,omitempty"` // empty: the DHCP-provided default
}

func (m *Manager) dnsBackupPath() string {
	return filepath.Join(filepath.Dir(m.backup), "system-dns-backup.json")
}

func (m *Manager) getDNS(service string) ([]string, error) {
	output, err := m.run("-getdnsservers", service)
	if err != nil {
		return nil, err
	}
	if strings.Contains(output, "There aren't any") {
		return nil, nil
	}
	var servers []string
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			servers = append(servers, line)
		}
	}
	return servers, nil
}

func (m *Manager) setDNS(service string, servers []string) error {
	if len(servers) == 0 {
		servers = []string{"Empty"}
	}
	_, err := m.run(append([]string{"-setdnsservers", service}, servers...)...)
	return err
}

// SetDNS points every enabled service's DNS at server, saving the originals
// first (a backup left by a crashed run is kept).
func (m *Manager) SetDNS(server string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	services, err := m.Services()
	if err != nil {
		return err
	}
	var saved []dnsBackup
	if data, err := os.ReadFile(m.dnsBackupPath()); err == nil {
		json.Unmarshal(data, &saved)
	}
	known := map[string]bool{}
	for _, entry := range saved {
		known[entry.Service] = true
	}
	for _, name := range services {
		if known[name] {
			continue
		}
		servers, err := m.getDNS(name)
		if err != nil {
			return err
		}
		saved = append(saved, dnsBackup{Service: name, Servers: servers})
	}
	data, _ := json.MarshalIndent(saved, "", "  ")
	if err := os.MkdirAll(filepath.Dir(m.dnsBackupPath()), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(m.dnsBackupPath(), data, 0o600); err != nil {
		return err
	}
	for _, name := range services {
		if err := m.setDNS(name, []string{server}); err != nil {
			return err
		}
	}
	return nil
}

// RestoreDNS puts the saved DNS settings back.
func (m *Manager) RestoreDNS() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := os.ReadFile(m.dnsBackupPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved []dnsBackup
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	var failed []string
	for _, entry := range saved {
		if err := m.setDNS(entry.Service, entry.Servers); err != nil {
			failed = append(failed, err.Error())
		}
	}
	if len(failed) != 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return os.Remove(m.dnsBackupPath())
}
