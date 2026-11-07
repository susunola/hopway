package engine

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"mac-proxy/internal/process"
)

func TestRuleSemantics(t *testing.T) {
	rules := []Rule{
		{Type: RuleDomain, Value: "exact.example.com", Via: "A"},
		{Type: RuleDomainKeyword, Value: "track", Via: "REJECT"},
		{Type: RuleDomainSuffix, Value: "example.com", Via: "B"},
		{Type: RuleIPCIDR, Value: "10.0.0.0/8", Via: "C", NoResolve: true},
		{Type: RuleIPCIDR, Value: "203.0.113.0/24", Via: "D"},
		{Type: RuleDomainSuffix, Value: "late.test", Via: "E"},
		{Type: RuleIPCIDR, Value: "2001:db8::/32", Via: "F"},
		{Type: RuleMatch, Via: "G"},
	}
	m, err := newMatcher(rules, func(string) bool { return true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	dns := map[string][]netip.Addr{
		"late.test":    {netip.MustParseAddr("203.0.113.9")},
		"private.test": {netip.MustParseAddr("10.1.2.3")},
	}
	resolved := 0
	resolve := func(host string) []netip.Addr { resolved++; return dns[host] }
	cases := []struct{ host, via string }{
		{"exact.example.com", "A"},
		{"EXACT.example.com.", "A"},
		{"a.example.com", "B"},
		{"example.com", "B"},
		{"notexample.com", "G"},
		{"tracker.example.com", "REJECT"}, // keyword precedes the suffix rule
		{"10.9.9.9", "C"},
		{"203.0.113.5", "D"},
		{"::ffff:203.0.113.5", "D"},
		{"[2001:db8::1]", "F"},
		{"late.test", "D"},    // resolved IP rule comes before the suffix rule
		{"private.test", "G"}, // no-resolve rules never match resolved names
	}
	for _, c := range cases {
		index := m.match(c.host, resolve, nil)
		got := "none"
		if index >= 0 {
			got = rules[index].Via
		}
		if got != c.via {
			t.Errorf("%s: got %s, want %s", c.host, got, c.via)
		}
	}
	// a.example.com matched rule 3 before any resolvable IP rule: no lookup.
	resolved = 0
	m.match("a.example.com", resolve, nil)
	if resolved != 0 {
		t.Fatal("resolved a name that a domain rule already decided")
	}
}

func TestRuleValidation(t *testing.T) {
	for _, rules := range [][]Rule{
		{{Type: RuleMatch, Via: "X"}, {Type: RuleDomain, Value: "a.test", Via: "X"}},
		{{Type: RuleIPCIDR, Value: "nonsense", Via: "X"}},
		{{Type: RuleDomain, Value: "*.wild", Via: "X"}},
		{{Type: "geoip", Value: "CN", Via: "X"}},
	} {
		if _, err := newMatcher(rules, func(string) bool { return true }, nil); err == nil {
			t.Errorf("accepted invalid rules %+v", rules)
		}
	}
}

func bigRuleSet(n int) []Rule {
	rules := make([]Rule, 0, n+1)
	for i := 0; i < n; i++ {
		switch i % 4 {
		case 0:
			rules = append(rules, Rule{Type: RuleDomainSuffix, Value: fmt.Sprintf("site%d.example", i), Via: "P"})
		case 1:
			rules = append(rules, Rule{Type: RuleDomain, Value: fmt.Sprintf("host%d.example", i), Via: "P"})
		case 2:
			rules = append(rules, Rule{Type: RuleIPCIDR, Value: fmt.Sprintf("10.%d.%d.0/24", i>>16&255, i>>8&255), Via: "P", NoResolve: true})
		default:
			rules = append(rules, Rule{Type: RuleIPCIDR, Value: fmt.Sprintf("2001:db8:%x::/48", i&0xffff), Via: "P", NoResolve: true})
		}
	}
	return append(rules, Rule{Type: RuleMatch, Via: "DIRECT"})
}

func BenchmarkMatch100k(b *testing.B) {
	m, err := newMatcher(bigRuleSet(100_000), func(string) bool { return true }, nil)
	if err != nil {
		b.Fatal(err)
	}
	hosts := []string{"www.site99996.example", "host50001.example", "unknown.example.org", "10.1.2.3", "2001:db8:42::1"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.match(hosts[i%len(hosts)], nil, nil)
	}
}

func TestProcessRules(t *testing.T) {
	rules := []Rule{
		{Type: RuleDomainSuffix, Value: "early.test", Via: "A"},
		{Type: RuleProcessName, Value: "Telegram.app", Via: "B"},
		{Type: RuleProcessPath, Value: "/usr/local/bin/", Via: "C"},
		{Type: RuleProcessPath, Value: "/usr/bin/curl", Via: "D"},
		{Type: RuleMatch, Via: "E"},
	}
	m, err := newMatcher(rules, func(string) bool { return true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string]*process.Owner{
		"telegram": {Name: "Telegram", App: "Telegram", Path: "/Applications/Telegram.app/Contents/MacOS/Telegram"},
		"brew":     {Name: "wget", Path: "/usr/local/bin/wget"},
		"curl":     {Name: "curl", Path: "/usr/bin/curl"},
		"other":    {Name: "Safari", App: "Safari", Path: "/Applications/Safari.app/Contents/MacOS/Safari"},
	}
	for name, want := range map[string]string{"telegram": "B", "brew": "C", "curl": "D", "other": "E"} {
		calls := 0
		owner := func() *process.Owner { calls++; return owners[name] }
		if got := rules[m.match("x.test", nil, owner)].Via; got != want || calls != 1 {
			t.Errorf("%s: got %s (lookups %d), want %s", name, got, calls, want)
		}
	}
	calls := 0
	if got := rules[m.match("a.early.test", nil, func() *process.Owner { calls++; return nil })].Via; got != "A" || calls != 0 {
		t.Errorf("an earlier domain rule must win without a process lookup (got %s, %d lookups)", got, calls)
	}
}

func TestScopedIPv6RouteRespectsLocalInterfaceAndExplicitRejection(t *testing.T) {
	rules := []Rule{
		{Type: RuleIPCIDR, Value: "fe80::123/128", Via: "REJECT", NoResolve: true},
		{Type: RuleMatch, Via: "SELECT"},
	}
	m, err := newMatcher(rules, func(string) bool { return true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{rules: m}
	for _, sample := range []struct {
		host, mode, selected, want string
	}{
		{"fe80::123%en9", "rule", "proxy", "REJECT"},
		{"fe80::124%en9", "rule", "proxy", "DIRECT"},
		{"fe80::124%en9", "global", "proxy", "DIRECT"},
		{"fe80::124%en9", "global", "REJECT", "REJECT"},
		{"fe80::124%en9", "rule", "REJECT", "REJECT"},
		{"fe80::124%en9", "auto", "proxy", "DIRECT"},
		{"2001:db8::2", "global", "proxy", "proxy"},
	} {
		if got, _ := e.route(context.Background(), sample.host, Policy{Mode: sample.mode, Selected: sample.selected}, nil); got != sample.want {
			t.Errorf("%s in %s mode via %s, want %s", sample.host, sample.mode, got, sample.want)
		}
	}
}
