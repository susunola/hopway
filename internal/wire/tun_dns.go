package wire

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

const MaxFakeIPExceptions = 128

func ValidateTUNDNSTimeout(ms int) error {
	if ms != 0 && (ms < 250 || ms > 15000) {
		return fmt.Errorf("tun.dnsTimeoutMs must be between 250 and 15000")
	}
	return nil
}

// FakeIPExceptions matches whole DNS labels and is immutable after construction.
type FakeIPExceptions map[string]struct{}

func ParseFakeIPExceptions(entries []string) (FakeIPExceptions, error) {
	if len(entries) > MaxFakeIPExceptions {
		return nil, fmt.Errorf("tun.fakeIPExceptions allows at most %d suffixes", MaxFakeIPExceptions)
	}
	if len(entries) == 0 {
		return nil, nil
	}
	result := make(FakeIPExceptions, len(entries))
	for i, entry := range entries {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(entry), "."), "."))
		if !validDNSSuffix(name) {
			return nil, fmt.Errorf("tun.fakeIPExceptions entry %d must be a domain suffix", i+1)
		}
		result[name] = struct{}{}
	}
	return result, nil
}

func validDNSSuffix(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func (entries FakeIPExceptions) Contains(name string) bool {
	if len(entries) == 0 {
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for offset, end := 0, false; !end; offset, end = dns.NextLabel(name, offset) {
		if _, ok := entries[name[offset:]]; ok {
			return true
		}
	}
	return false
}
