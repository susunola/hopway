package engine

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"mac-proxy/internal/process"
	"mac-proxy/internal/ruleset"
)

func TestRuleSemantics(t *testing.T) {
	rules := []Rule{
		{Type: RuleDomain, Value: "exact.example.com", Via: "A"},
		{Type: RuleDomain, Value: "1.2.3.test", Via: "A"},
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
		{"1.2.3.test", "A"},
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
	// a.example.com matched a domain rule before any resolvable IP rule: no lookup.
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

func TestOverlappingCIDRsRespectConfiguredOrder(t *testing.T) {
	for _, family := range []struct{ broad, narrow, inside, outside string }{
		{"192.0.0.0/16", "192.0.2.0/24", "192.0.2.42", "192.0.3.42"},
		{"2001:db8::/32", "2001:db8:2::/48", "2001:db8:2::42", "2001:db8:3::42"},
	} {
		for _, broadFirst := range []bool{false, true} {
			broad := Rule{Type: RuleIPCIDR, Value: family.broad, Via: "broad"}
			narrow := Rule{Type: RuleIPCIDR, Value: family.narrow, Via: "narrow"}
			rules := []Rule{narrow, broad}
			if broadFirst {
				rules[0], rules[1] = rules[1], rules[0]
			}
			m, err := newMatcher(rules, func(string) bool { return true }, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct{ addr, want string }{{family.inside, rules[0].Via}, {family.outside, "broad"}} {
				resolve := func(string) []netip.Addr { return []netip.Addr{netip.MustParseAddr(test.addr)} }
				literal, resolved := m.match(test.addr, nil, nil), m.match("resolved.test", resolve, nil)
				if literal < 0 || resolved != literal || rules[literal].Via != test.want {
					t.Errorf("%s broadFirst=%t: literal index %d, resolved index %d, want %s", test.addr, broadFirst, literal, resolved, test.want)
				}
			}
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

func BenchmarkMatchRuleCounts(b *testing.B) {
	for _, count := range []int{10_000, 100_000, 500_000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			m, err := newMatcher(bigRuleSet(count), func(string) bool { return true }, nil)
			if err != nil {
				b.Fatal(err)
			}
			hosts := []string{fmt.Sprintf("www.site%d.example", count-4), "host5001.example",
				"unknown.example.org", "10.1.2.3", "2001:db8:42::1"}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				m.match(hosts[i%len(hosts)], nil, nil)
				i++
			}
		})
	}
}

func BenchmarkCompoundRuleMatch(b *testing.B) {
	content, err := ruleset.Parse(ruleset.FormatText, ruleset.BehaviorClassical, []byte("DOMAIN,listed.example\nIP-CIDR,192.0.2.0/24\n"))
	if err != nil {
		b.Fatal(err)
	}
	sets := []*ruleSetState{{RuleSet: RuleSet{Name: "mixed"}, content: content}}
	m, err := newMatcher([]Rule{
		{Type: RuleProcessName, Value: "relay", Via: "DIRECT"},
		{Type: RuleRuleSet, Value: "mixed", Via: "REJECT"},
		{Type: RuleMatch, Via: "DIRECT"},
	}, func(string) bool { return true }, sets)
	if err != nil {
		b.Fatal(err)
	}
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	resolve := func(string) []netip.Addr { return addresses }
	application := process.Owner{Name: "unknown"}
	owner := func() *process.Owner { return &application }
	hosts := []string{"listed.example", "unlisted.example", "192.0.2.10"}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if result := m.match(hosts[i%len(hosts)], resolve, owner); result != 1 {
			b.Fatalf("unexpected route %d", result)
		}
		i++
	}
}

func BenchmarkPolicyDepth(b *testing.B) {
	for _, depth := range []int{1, 4, 8} {
		b.Run(fmt.Sprint(depth), func(b *testing.B) {
			config := Default()
			name := "DIRECT"
			for level := range depth {
				group := fmt.Sprintf("level-%d", level)
				config.Groups = append(config.Groups, Group{Name: group, Type: GroupSelect, Members: []string{name}})
				name = group
			}
			proxy, err := New(config, nil)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			var samples [16384]time.Duration
			i := 0
			for b.Loop() {
				start := time.Now()
				result := proxy.choices(name)
				samples[i%len(samples)] = time.Since(start)
				if len(result) != 1 || len(result[0].route) != depth || result[0].via != "DIRECT" {
					b.Fatal("unexpected nested route")
				}
				i++
			}
			observed := samples[:min(i, len(samples))]
			slices.Sort(observed)
			b.ReportMetric(float64(observed[(len(observed)-1)*95/100].Nanoseconds()), "p95-ns")
		})
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

func TestProcessBundleRoutingUsesFirstRuleAndFallsThroughOnUnknown(t *testing.T) {
	config := Default()
	config.Rules = []Rule{
		{Type: RuleProcessPath, Value: "/Applications/First.app/", Via: "DIRECT"},
		{Type: RuleProcessBundle, Value: "org.example.Browser", Via: "REJECT"},
		{Type: RuleMatch, Via: "DIRECT"},
	}
	core, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		owner *process.Owner
		want  int
	}{
		{&process.Owner{BundleID: "ORG.EXAMPLE.BROWSER", Path: "/Applications/First.app/Contents/MacOS/Browser"}, 0},
		{&process.Owner{BundleID: "org.example.Browser", Path: "/Moved/Browser.app/Contents/MacOS/Helper"}, 1},
		{&process.Owner{Path: "/Moved/Browser.app/Contents/MacOS/Helper"}, 2},
		{nil, 2},
	} {
		if got := core.rules.match("example.test", nil, func() *process.Owner { return test.owner }); got != test.want {
			t.Fatalf("owner %+v matched %d, want %d", test.owner, got, test.want)
		}
	}
	config.Rules[1].Value = "com.example..Bad identifier"
	if _, err := New(config, nil); err == nil {
		t.Fatal("accepted a malformed bundle identifier")
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
		if got, _, _ := e.route(context.Background(), sample.host, Policy{Mode: sample.mode, Selected: sample.selected}, nil); got != sample.want {
			t.Errorf("%s in %s mode via %s, want %s", sample.host, sample.mode, got, sample.want)
		}
	}
}
