// Package dnsconf resolves hop destinations through user-configured servers
// instead of the system resolver, so a domain can use a faster or unblocked
// upstream and the connection detail can say which one answered.
package dnsconf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Server is one upstream. Address is numeric ("1.1.1.1:53"); "system" is the
// reserved name for the platform resolver.
type Server struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// Rule maps a domain suffix to a server. The first matching rule wins.
type Rule struct {
	Domain string `json:"domain"`
	Server string `json:"server"`
}

// Config is the on-disk form. An empty config means "system resolver only".
type Config struct {
	Servers []Server `json:"servers,omitempty"`
	Rules   []Rule   `json:"rules,omitempty"`
	Default string   `json:"default,omitempty"`
}

const SystemServer = "system"

func (config Config) Validate() error {
	names := map[string]bool{}
	for _, server := range config.Servers {
		if server.Name == "" || names[server.Name] {
			return fmt.Errorf("dns server name %q is empty or duplicated", server.Name)
		}
		if server.Name == SystemServer {
			return fmt.Errorf("dns server name %q is reserved", server.Name)
		}
		names[server.Name] = true
		if server.Address != SystemServer {
			if _, _, err := splitAddress(server.Address); err != nil {
				return fmt.Errorf("dns server %q: %w", server.Name, err)
			}
		}
	}
	if config.Default != "" && config.Default != SystemServer && !names[config.Default] {
		return fmt.Errorf("dns default refers to unknown server %q", config.Default)
	}
	for index, rule := range config.Rules {
		if strings.TrimSpace(rule.Domain) == "" {
			return fmt.Errorf("dns rule %d has no domain", index+1)
		}
		if rule.Server != SystemServer && !names[rule.Server] {
			return fmt.Errorf("dns rule %d refers to unknown server %q", index+1, rule.Server)
		}
	}
	return nil
}

func splitAddress(address string) (string, uint16, error) {
	host, port, err := netSplitHostPort(address)
	if err != nil {
		return "", 0, errors.New("address must be host:port")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return "", 0, errors.New("address must be numeric, not a host name")
	}
	return host, port, nil
}

func netSplitHostPort(address string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return "", 0, errors.New("invalid port")
	}
	return host, uint16(number), nil
}

func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// DialFunc opens the UDP socket for a query. Callers pass the proxy's own
// dialer so a TUN-mode lookup leaves through the physical interface instead
// of looping back into the tunnel.
type DialFunc func(context.Context, string, string) (net.Conn, error)

// Resolver answers A and AAAA queries, caching by (server, host).
type Resolver struct {
	config Config
	dial   DialFunc
	mu     sync.Mutex
	cache  map[cacheKey]cacheEntry
}

type cacheKey struct{ server, host string }

type cacheEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

const (
	cacheTTL  = 60 * time.Second
	queryTime = 5 * time.Second
)

// New validates config and returns a resolver. A nil config gives one that
// always asks the system resolver.
func New(config *Config, dial DialFunc) (*Resolver, error) {
	resolver := &Resolver{cache: map[cacheKey]cacheEntry{}, dial: dial}
	if config == nil {
		return resolver, nil
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	resolver.config = *config
	return resolver, nil
}

// ServerFor returns the server name that will answer for host.
func (resolver *Resolver) ServerFor(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, rule := range resolver.config.Rules {
		suffix := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(rule.Domain), "."))
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return rule.Server
		}
	}
	if resolver.config.Default != "" {
		return resolver.config.Default
	}
	return SystemServer
}

// Lookup resolves host and reports which server (or "system") answered.
func (resolver *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, string, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, "", nil
	}
	server := resolver.ServerFor(host)
	key := cacheKey{server: server, host: strings.ToLower(host)}
	resolver.mu.Lock()
	entry, ok := resolver.cache[key]
	resolver.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.addrs, server, nil
	}

	var addrs []netip.Addr
	var err error
	if server == SystemServer {
		addrs, err = systemLookup(ctx, host)
	} else {
		addrs, err = resolver.query(ctx, server, host)
	}
	if err != nil || len(addrs) == 0 {
		if err == nil {
			err = errors.New("no addresses for " + host)
		}
		return nil, server, err
	}
	sort.SliceStable(addrs, func(i, j int) bool { return addrs[i].Is4() && !addrs[j].Is4() })
	resolver.mu.Lock()
	if len(resolver.cache) > 4096 {
		resolver.cache = map[cacheKey]cacheEntry{}
	}
	resolver.cache[key] = cacheEntry{addrs: addrs, expires: time.Now().Add(cacheTTL)}
	resolver.mu.Unlock()
	return addrs, server, nil
}

func (resolver *Resolver) address(name string) (string, bool) {
	for _, server := range resolver.config.Servers {
		if server.Name == name {
			return server.Address, true
		}
	}
	return "", false
}

func (resolver *Resolver) query(ctx context.Context, server, host string) ([]netip.Addr, error) {
	address, ok := resolver.address(server)
	if !ok {
		return nil, fmt.Errorf("unknown dns server %q", server)
	}
	ctx, cancel := context.WithTimeout(ctx, queryTime)
	defer cancel()
	client := &dns.Client{Net: "udp", Timeout: queryTime}
	open := resolver.dial
	if open == nil {
		open = (&net.Dialer{}).DialContext
	}
	var addrs []netip.Addr
	var lastErr error
	for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(host), kind)
		message.RecursionDesired = true
		raw, err := open(ctx, "udp", address)
		if err != nil {
			lastErr = err
			continue
		}
		response, _, err := client.ExchangeWithConn(message, &dns.Conn{Conn: raw})
		raw.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if response.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("dns server %s answered %s", server, dns.RcodeToString[response.Rcode])
			continue
		}
		for _, record := range response.Answer {
			switch typed := record.(type) {
			case *dns.A:
				if addr, ok := netip.AddrFromSlice(typed.A); ok {
					addrs = append(addrs, addr.Unmap())
				}
			case *dns.AAAA:
				if addr, ok := netip.AddrFromSlice(typed.AAAA); ok {
					addrs = append(addrs, addr.Unmap())
				}
			}
		}
	}
	if len(addrs) == 0 && lastErr == nil {
		lastErr = errors.New("empty answer")
	}
	return addrs, lastErr
}
