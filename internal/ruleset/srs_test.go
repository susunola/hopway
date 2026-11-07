//go:build !hopway_native

package ruleset

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestSRS(t *testing.T) {
	plain := option.PlainRuleSet{Rules: []option.HeadlessRule{
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{
			Domain: []string{"exact.cn"}, DomainSuffix: []string{"baidu.com", ".sub.cn"}, DomainKeyword: []string{"taobao"},
			IPCIDR: []string{"1.0.1.0/24", "240e::/20"},
		}},
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{Domain: []string{"port-only.cn"}, Port: []uint16{443}}},
	}}
	var buffer bytes.Buffer
	if err := srs.Write(&buffer, plain, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	content, err := Parse(FormatSRS, "", buffer.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if content.Skipped != 1 {
		t.Fatalf("a port-restricted rule must be skipped, got %+v", content)
	}
	for host, want := range map[string]bool{"exact.cn": true, "www.baidu.com": true, "baidu.com": true, "sub.cn": false,
		"a.sub.cn": true, "m.taobao.com": true, "port-only.cn": false} {
		if content.MatchDomain(host) != want {
			t.Errorf("%s: want %v", host, want)
		}
	}
	if !content.MatchIP(netip.MustParseAddr("1.0.1.7")) || !content.MatchIP(netip.MustParseAddr("240e::1")) || content.MatchIP(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("srs IP matching")
	}
}
