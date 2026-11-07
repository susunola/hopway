package ruleset

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestLargeYAMLBlockPayloadMatchesNormalDecoder(t *testing.T) {
	const sample = "payload: # fixture\n  - '+.alpha.test' # note\n  - \"*.beta.test\"\n  - gamma.test\n  - raw#fragment.test\n  - null\n"
	data := append([]byte(sample), bytes.Repeat([]byte("# pad for a large rule set\n"), 100_000)...)
	large, err := Parse(FormatYAML, BehaviorDomain, data)
	if err != nil {
		t.Fatal(err)
	}
	small, err := Parse(FormatYAML, BehaviorDomain, []byte(sample))
	if err != nil || large.Entries != small.Entries {
		t.Fatalf("large and small YAML disagree: %d, %v, %v", large.Entries, small, err)
	}
	for _, name := range []string{"alpha.test", "one.alpha.test", "beta.test", "one.beta.test", "gamma.test", "raw#fragment.test", "null"} {
		if large.MatchDomain(name) != small.MatchDomain(name) {
			t.Errorf("large and small YAML disagree for %s", name)
		}
	}
}

func TestRuleSetRejectsExpensiveYAMLAndRegex(t *testing.T) {
	flow := []byte("payload: [\n" + strings.Repeat("  [],\n", maxGeneralYAMLSize/6) + "]")
	if content, err := Parse(FormatYAML, BehaviorDomain, flow); content != nil || err == nil || !strings.Contains(err.Error(), "block payload") {
		t.Fatalf("large YAML flow collection returned %v, %v", content, err)
	}
	data := []byte("DOMAIN,valid.test\nDOMAIN-REGEX,(abcdefghijklmno){1000}\n")
	if content, err := Parse(FormatText, BehaviorClassical, data); content != nil || !errors.Is(err, errRuleSetBudget) {
		t.Fatalf("expensive regex returned %v, %v", content, err)
	}
}

func TestClashFormats(t *testing.T) {
	domain, err := Parse(FormatYAML, BehaviorDomain, []byte("payload:\n  - '+.google.com'\n  - '.only-sub.test'\n  - 'exact.test'\n  - '*.wild.test'\n"))
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"google.com": true, "a.google.com": true, "notgoogle.com": false,
		"only-sub.test": false, "a.only-sub.test": true, "exact.test": true, "a.exact.test": false,
		"wild.test": false, "x.wild.test": true,
	} {
		if domain.MatchDomain(host) != want {
			t.Errorf("domain %s: want %v", host, want)
		}
	}
	ip, err := Parse(FormatText, BehaviorIPCIDR, []byte("# comment\n10.0.0.0/8\n2001:db8::/32\n1.1.1.1\nbogus\n"))
	if err != nil || ip.Entries != 3 || ip.Skipped != 1 {
		t.Fatalf("ipcidr %+v %v", ip, err)
	}
	if !ip.MatchIP(netip.MustParseAddr("10.2.3.4")) || !ip.MatchIP(netip.MustParseAddr("::ffff:1.1.1.1")) || ip.MatchIP(netip.MustParseAddr("1.1.1.2")) {
		t.Fatal("ipcidr matching")
	}
	classical, err := Parse(FormatText, BehaviorClassical, []byte("DOMAIN-SUFFIX,apple.com\nDOMAIN-KEYWORD,ads\nDOMAIN-REGEX,^api\\d+\\.x\\.test$\nIP-CIDR,17.0.0.0/8,no-resolve\nPROCESS-NAME,Mail\nDST-PORT,443\n"))
	if err != nil || classical.Entries != 4 || classical.Skipped != 2 {
		t.Fatalf("classical %+v %v", classical, err)
	}
	for host, want := range map[string]bool{"www.apple.com": true, "myads.net": true, "api42.x.test": true, "apix.x.test": false} {
		if classical.MatchDomain(host) != want {
			t.Errorf("classical %s: want %v", host, want)
		}
	}
}
