package engine

import (
	"fmt"
	"net/netip"
	"strings"

	"mac-proxy/internal/process"
)

// Rule types, matching Clash semantics where they overlap.
const (
	RuleDomain        = "domain"
	RuleDomainSuffix  = "domain-suffix"
	RuleDomainKeyword = "domain-keyword"
	RuleIPCIDR        = "ip-cidr"
	RuleMatch         = "match"
	RuleProcessName   = "process-name" // executable name or .app bundle name, case-insensitive
	RuleProcessPath   = "process-path" // exact executable path, or a prefix ending in "/"
)

type Rule struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Via       string `json:"via"`
	NoResolve bool   `json:"noResolve,omitempty"`
}

func (rule Rule) String() string {
	text := strings.TrimSpace(rule.Type + " " + rule.Value)
	if rule.NoResolve {
		text += " (no-resolve)"
	}
	return text
}

const none = int(^uint(0) >> 1)

// matcher evaluates first-match-wins rule lists with indexed lookups, so a
// 100k-line rule set costs a few map probes per connection instead of a scan.
type matcher struct {
	rules    []Rule
	exact    map[string]int
	suffix   map[string]int
	keywords []indexed
	ip       prefixSet // every ip-cidr rule, used for literal IP targets
	resolved prefixSet // ip-cidr rules allowed to trigger DNS for domain targets
	procName map[string]int
	procPath map[string]int
	procDirs []indexed
	procMin  int
	final    int
}

type indexed struct {
	value string
	index int
}

type prefixSet struct {
	byPrefix map[netip.Prefix]int
	lengths4 []int
	lengths6 []int
	first    int
}

func (set *prefixSet) add(prefix netip.Prefix, index int) {
	if set.byPrefix == nil {
		set.byPrefix, set.first = make(map[netip.Prefix]int), none
	}
	prefix = prefix.Masked()
	if _, exists := set.byPrefix[prefix]; exists {
		return // an earlier rule with the same prefix always wins
	}
	set.byPrefix[prefix] = index
	set.first = min(set.first, index)
	lengths := &set.lengths6
	if prefix.Addr().Is4() {
		lengths = &set.lengths4
	}
	for _, bits := range *lengths {
		if bits == prefix.Bits() {
			return
		}
	}
	*lengths = append(*lengths, prefix.Bits())
}

func (set *prefixSet) lookup(addr netip.Addr) int {
	best := none
	if set.byPrefix == nil {
		return best
	}
	addr = addr.Unmap()
	lengths := set.lengths6
	if addr.Is4() {
		lengths = set.lengths4
	}
	for _, bits := range lengths {
		prefix, err := addr.Prefix(bits)
		if err != nil {
			continue
		}
		if index, ok := set.byPrefix[prefix]; ok && index < best {
			best = index
		}
	}
	return best
}

func newMatcher(rules []Rule, valid func(string) bool) (*matcher, error) {
	m := &matcher{exact: make(map[string]int), suffix: make(map[string]int), final: none,
		procName: make(map[string]int), procPath: make(map[string]int), procMin: none,
		ip: prefixSet{first: none}, resolved: prefixSet{first: none}}
	for index, rule := range rules {
		if !valid(rule.Via) {
			return nil, fmt.Errorf("rule %d refers to unknown outbound %q", index+1, rule.Via)
		}
		switch rule.Type {
		case RuleDomain, RuleDomainSuffix, RuleDomainKeyword:
			rule.Value = normalizeHost(rule.Value)
			if rule.Value == "" || strings.ContainsAny(rule.Value, "/: *") {
				return nil, fmt.Errorf("rule %d needs a domain name", index+1)
			}
			table := m.exact
			switch rule.Type {
			case RuleDomainSuffix:
				table = m.suffix
			case RuleDomainKeyword:
				m.keywords = append(m.keywords, indexed{rule.Value, index})
				table = nil
			}
			if table != nil {
				if _, exists := table[rule.Value]; !exists {
					table[rule.Value] = index
				}
			}
		case RuleIPCIDR:
			prefix, err := netip.ParsePrefix(rule.Value)
			if err != nil {
				addr, addrErr := netip.ParseAddr(rule.Value)
				if addrErr != nil {
					return nil, fmt.Errorf("rule %d has an invalid IP prefix", index+1)
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			if prefix.Addr().Is4In6() {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), max(prefix.Bits()-96, 0))
			}
			m.ip.add(prefix, index)
			if !rule.NoResolve {
				m.resolved.add(prefix, index)
			}
		case RuleProcessName:
			name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Value), ".app"))
			if name == "" || strings.Contains(name, "/") {
				return nil, fmt.Errorf("rule %d needs a process or app name", index+1)
			}
			rule.Value = name
			if _, exists := m.procName[name]; !exists {
				m.procName[name] = index
			}
			m.procMin = min(m.procMin, index)
		case RuleProcessPath:
			if !strings.HasPrefix(rule.Value, "/") {
				return nil, fmt.Errorf("rule %d needs an absolute path", index+1)
			}
			if strings.HasSuffix(rule.Value, "/") {
				m.procDirs = append(m.procDirs, indexed{rule.Value, index})
			} else if _, exists := m.procPath[rule.Value]; !exists {
				m.procPath[rule.Value] = index
			}
			m.procMin = min(m.procMin, index)
		case RuleMatch:
			if rule.Value != "" || index != len(rules)-1 {
				return nil, fmt.Errorf("rule %d: match must be the last rule and have no value", index+1)
			}
			m.final = index
		default:
			return nil, fmt.Errorf("rule %d has unknown type %q", index+1, rule.Type)
		}
		m.rules = append(m.rules, rule)
	}
	return m, nil
}

// match returns the index of the first matching rule, or -1. resolve is
// called at most once, and only if an IP rule could beat every domain match;
// owner likewise only if a process rule could.
func (m *matcher) match(host string, resolve func(string) []netip.Addr, owner func() *process.Owner) int {
	host = normalizeHost(host)
	best := m.final
	if addr, err := netip.ParseAddr(host); err == nil {
		best = min(best, m.ip.lookup(addr))
		return found(m.matchProcess(best, owner))
	}
	if index, ok := m.exact[host]; ok {
		best = min(best, index)
	}
	for name := host; ; {
		if index, ok := m.suffix[name]; ok {
			best = min(best, index)
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			break
		}
		name = name[dot+1:]
	}
	for _, keyword := range m.keywords {
		if keyword.index >= best {
			break
		}
		if strings.Contains(host, keyword.value) {
			best = keyword.index
		}
	}
	best = m.matchProcess(best, owner)
	if m.resolved.first < best && resolve != nil {
		for _, addr := range resolve(host) {
			best = min(best, m.resolved.lookup(addr))
		}
	}
	return found(best)
}

// matchProcess runs before DNS: finding the process is a local table lookup,
// much cheaper than a resolver round trip.
func (m *matcher) matchProcess(best int, owner func() *process.Owner) int {
	if m.procMin >= best || owner == nil {
		return best
	}
	o := owner()
	if o == nil {
		return best
	}
	for _, name := range []string{o.Name, o.App} {
		if index, ok := m.procName[strings.ToLower(name)]; ok && name != "" {
			best = min(best, index)
		}
	}
	if index, ok := m.procPath[o.Path]; ok {
		best = min(best, index)
	}
	for _, dir := range m.procDirs {
		if dir.index < best && strings.HasPrefix(o.Path, dir.value) {
			best = dir.index
		}
	}
	return best
}

func found(index int) int {
	if index == none {
		return -1
	}
	return index
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
}
