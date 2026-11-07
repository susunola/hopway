package sysproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// DNS settings are changed in TUN mode so that queries to a DNS server on
// the local network (which has its own route and would bypass the tunnel)
// reach HopWay. They are backed up and restored like the proxy settings.

type dnsBackup struct {
	Service string   `json:"service"`
	Servers []string `json:"servers,omitempty"` // empty: the DHCP-provided default
	Applied string   `json:"applied,omitempty"`
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

func (m *Manager) readDNSBackup() ([]dnsBackup, error) {
	data, err := os.ReadFile(m.dnsBackupPath())
	if err != nil {
		return nil, err
	}
	var saved []dnsBackup
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, err
	}
	return saved, nil
}

// SetDNS saves original values before changing any service. If a service
// rejects the change, roll back the services affected by this attempt.
func (m *Manager) SetDNS(server string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	services, err := m.Services()
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return errors.New("no enabled network service")
	}
	saved, err := m.readDNSBackup()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read original DNS settings: %w", err)
	}
	known := map[string]string{}
	for _, entry := range saved {
		known[entry.Service] = entry.Applied
	}
	var added []dnsBackup
	for _, name := range services {
		if applied, ok := known[name]; ok {
			if applied != server {
				return errors.New("restore the previous DNS settings before changing the target")
			}
			continue
		}
		servers, err := m.getDNS(name)
		if err != nil {
			return err
		}
		added = append(added, dnsBackup{Service: name, Servers: servers, Applied: server})
	}
	if len(added) == 0 {
		return nil
	}
	if err := writeBackup(m.dnsBackupPath(), append(saved, added...)); err != nil {
		return err
	}
	for _, entry := range added {
		if err := m.setDNS(entry.Service, []string{server}); err != nil {
			if restoreErr := m.restoreDNS(added); restoreErr != nil {
				return errors.Join(err, restoreErr)
			}
			if len(saved) == 0 {
				return errors.Join(err, os.Remove(m.dnsBackupPath()))
			}
			return errors.Join(err, writeBackup(m.dnsBackupPath(), saved))
		}
	}
	return nil
}

func (m *Manager) restoreDNS(saved []dnsBackup) error {
	services, err := m.services(true)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range saved {
		if !slices.Contains(services, entry.Service) {
			continue
		}
		if entry.Applied != "" {
			current, err := m.getDNS(entry.Service)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if !slices.Equal(current, []string{entry.Applied}) {
				continue
			}
		}
		failures = append(failures, m.setDNS(entry.Service, entry.Servers))
	}
	return errors.Join(failures...)
}

// RestoreDNS puts the saved DNS settings back.
func (m *Manager) RestoreDNS() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	saved, err := m.readDNSBackup()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := m.restoreDNS(saved); err != nil {
		return err
	}
	return os.Remove(m.dnsBackupPath())
}
