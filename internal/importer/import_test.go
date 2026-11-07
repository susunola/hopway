package importer

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
)

func TestSubscriptionMergesSupportedNodes(t *testing.T) {
	const profile = `
proxies:
  - {name: Tokyo, type: vless, server: example.test, port: 443, uuid: ccc641c2-e296-455c-9f8e-8d13a9b02976, tls: true}
  - {name: Reality, type: vless, server: example.test, port: 443, flow: xtls-rprx-vision}
  - {name: Broken, type: socks5, server: example.test, port: wrong}
  - {name: Tokyo, type: socks5, server: example.test, port: 1080}
proxy-groups:
  - {name: Auto, type: url-test, proxies: [Tokyo]}
rules:
  - MATCH,Auto
`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("token") != "fixture-only" || !strings.HasPrefix(request.UserAgent(), "clash/") {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		writer.Write([]byte(profile))
	}))
	defer server.Close()

	config := engine.Default()
	config.Rules = []engine.Rule{{Type: "match", Via: "REJECT"}}
	result, err := Import(context.Background(), strings.NewReader(server.URL+"?token=fixture-only"), config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 2 || result.Skipped != 2 || len(result.Notes) != 3 ||
		result.Config.Nodes[0].Type != "vless" || result.Config.Nodes[1].Name != "Tokyo (2)" ||
		len(result.Config.Groups) != 1 || result.Config.Groups[0].Members[0] != "Tokyo" ||
		result.Config.Rules[0].Via != "Auto" || result.Config.Selected != "Auto" {
		t.Fatalf("unexpected import: %+v", result)
	}
	if _, err := Import(context.Background(), strings.NewReader(profile), result.Config, backend.Default()); err == nil {
		t.Fatal("repeat import unexpectedly added a duplicate")
	}
}

func TestBase64ShareLinks(t *testing.T) {
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"ps":"AEAD","add":"example.test","port":"443","id":"ccc641c2-e296-455c-9f8e-8d13a9b02976","aid":0,"net":"tcp","tls":"tls"}`))
	links := "ss://aes-128-gcm:demo@[2001:db8::1]:8388#Example\nvmess://" + vmess
	body := base64.StdEncoding.EncodeToString([]byte(links))
	result, err := Import(context.Background(), strings.NewReader(body), engine.Default(), backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 2 || result.Config.Nodes[0].Server != "[2001:db8::1]:8388" || !result.Config.Nodes[1].TLS {
		t.Fatalf("unexpected share-link import: %+v", result)
	}
}
