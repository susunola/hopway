//go:build !hopway_native

package ruleset

import (
	"net/netip"
	"os"
	"testing"
)

// Run with GEO_DIR pointing at real files from SagerNet/sing-geoip and sing-geosite.
func TestRealGeoFiles(t *testing.T) {
	dir := os.Getenv("GEO_DIR")
	if dir == "" {
		t.Skip("GEO_DIR not set")
	}
	load := func(name string) *Content {
		data, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		c, err := Parse(FormatSRS, "", data)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d entries, %d skipped", name, c.Entries, c.Skipped)
		return c
	}
	cnIP, cnSite, google := load("geoip-cn.srs"), load("geosite-cn.srs"), load("geosite-google.srs")
	for ip, want := range map[string]bool{"114.114.114.114": true, "223.5.5.5": true, "8.8.8.8": false, "1.1.1.1": false} {
		if cnIP.MatchIP(netip.MustParseAddr(ip)) != want {
			t.Errorf("geoip-cn %s: want %v", ip, want)
		}
	}
	for host, want := range map[string]bool{"www.baidu.com": true, "qq.com": true, "www.google.com": false} {
		if cnSite.MatchDomain(host) != want {
			t.Errorf("geosite-cn %s: want %v", host, want)
		}
	}
	for host, want := range map[string]bool{"www.google.com": true, "youtube.com": true, "www.baidu.com": false} {
		if google.MatchDomain(host) != want {
			t.Errorf("geosite-google %s: want %v", host, want)
		}
	}
}

func BenchmarkGeoSiteCN(b *testing.B) {
	dir := os.Getenv("GEO_DIR")
	if dir == "" {
		b.Skip("GEO_DIR not set")
	}
	data, _ := os.ReadFile(dir + "/geosite-cn.srs")
	c, _ := Parse(FormatSRS, "", data)
	hosts := []string{"www.baidu.com", "img.alicdn.com", "www.google.com", "a.b.c.example.org"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.MatchDomain(hosts[i%len(hosts)])
	}
}
