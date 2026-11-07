package ruleset

import (
	"net/netip"
	"testing"
)

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
