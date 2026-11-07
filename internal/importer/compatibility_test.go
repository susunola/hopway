package importer

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
)

func TestSubscriptionAppFormats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.UserAgent() == "v2rayNG" {
			writer.Write([]byte(base64.StdEncoding.EncodeToString([]byte("socks5://example.test:1080#Fixture"))))
			return
		}
		writer.Write([]byte("[General]\n[Proxy]\nFixture = ss, example.test, 8388, encrypt-method=aes-128-gcm, password=fixture\n[Rule]\nFINAL,Fixture"))
	}))
	defer server.Close()
	for _, prefix := range []string{"surge:///install-config", "surge3:///install-config", "surfboard:///install-config", "v2rayng://install-sub"} {
		t.Run(prefix, func(t *testing.T) {
			result, err := Import(context.Background(), strings.NewReader(prefix+"?url="+url.QueryEscape(server.URL)), engine.Default(), backend.Default())
			if err != nil || result.Added != 1 || result.Source != server.URL {
				t.Fatalf("compatible subscription failed: %v", err)
			}
		})
	}
}

func TestOneClickSubscriptionLinks(t *testing.T) {
	const source = "https://example.test/api/subscribe?token=fixture"
	for _, tc := range []struct {
		raw, agent string
	}{
		{"clash://install-config?url=" + source + "&name=%E5%A5%97%E9%A4%90", "Clash.Meta/HopWay"},
		{"clash://install-config?url=" + url.QueryEscape(source) + "&name=%E5%A5%97%E9%A4%90", "Clash.Meta/HopWay"},
		{"shadowrocket://add/sub://" + base64.RawStdEncoding.EncodeToString([]byte(source)) + "?remark=%E5%A5%97%E9%A4%90&allowInsecure=1", "Shadowrocket"},
	} {
		parsed, agent, name, err := SubscriptionLink(tc.raw)
		if err != nil || parsed == nil || parsed.String() != source || agent != tc.agent || name != "套餐" {
			t.Fatalf("wrapper failed: got %v, %q, %q, %v", parsed, agent, name, err)
		}
	}
}

func TestSubscriptionAnyTLSAlwaysVerifiesCertificates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Subscription-Userinfo", "upload=2; download=3; total=10")
		writer.Write([]byte("anytls://fixture@example.test:443?insecure=1#HK\n" +
			"anytls://fixture@example.test:443#%E8%AF%B7%E6%9B%B4%E6%96%B0%E5%AE%A2%E6%88%B7%E7%AB%AF"))
	}))
	defer server.Close()
	result, err := Import(context.Background(), strings.NewReader(server.URL), engine.Default(), backend.Default())
	if err != nil || result.Added != 1 || result.Skipped != 1 || result.Usage == nil || *result.Usage.Used != 5 {
		t.Fatalf("subscription import failed: %v", err)
	}
	if strings.Contains(string(result.Config.Nodes[0].Options), "insecure") {
		t.Fatal("subscription disabled verification")
	}
}
