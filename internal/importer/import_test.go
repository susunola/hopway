package importer

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
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
	result, err := Import(context.Background(), strings.NewReader(server.URL+"?token=fixture-only"), config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 2 || result.Skipped != 2 || len(result.Notes) != 3 ||
		result.Config.Nodes[0].Type != "vless" || result.Config.Nodes[1].Name != "Tokyo (2)" ||
		result.Config.Rules[0].Via != "REJECT" || result.Config.Selected != engine.Auto ||
		len(result.Config.Subscriptions) != 1 || result.Config.Nodes[0].Subscription != result.Config.Subscriptions[0].Name {
		t.Fatalf("unexpected import: %+v", result)
	}
	if _, err := Import(context.Background(), strings.NewReader(profile), result.Config); err == nil {
		t.Fatal("repeat import unexpectedly added a duplicate")
	}
}

func TestBase64ShareLinks(t *testing.T) {
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"ps":"AEAD","add":"example.test","port":"443","id":"ccc641c2-e296-455c-9f8e-8d13a9b02976","aid":0,"net":"tcp","tls":"tls"}`))
	links := "ss://aes-128-gcm:demo@[2001:db8::1]:8388#Example\nvmess://" + vmess
	body := base64.StdEncoding.EncodeToString([]byte(links))
	result, err := Import(context.Background(), strings.NewReader(body), engine.Default())
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 2 || result.Config.Nodes[0].Server != "[2001:db8::1]:8388" || !result.Config.Nodes[1].TLS {
		t.Fatalf("unexpected share-link import: %+v", result)
	}
}

func TestSubscriptionRefreshReplacesNodesAndReadsUsage(t *testing.T) {
	nodes := "trojan://secret@a.example.test:443#A\ntrojan://secret@b.example.test:443#B"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Subscription-Userinfo", "upload=1024; download=2048; total=10737418240; expire=1893456000")
		writer.Write([]byte(base64.StdEncoding.EncodeToString([]byte(nodes))))
	}))
	defer server.Close()

	config := engine.Default()
	config.Nodes = []outbound.Node{{Name: "Manual", Type: "socks5", Server: "manual.test:1080"}}
	config.Rules = []engine.Rule{{Type: "match", Via: "DIRECT"}}
	first, err := Import(context.Background(), strings.NewReader(server.URL), config)
	if err != nil {
		t.Fatal(err)
	}
	plan := first.Config.Subscriptions[0]
	if first.Added != 2 || plan.Upload != 1024 || plan.Download != 2048 || plan.Total != 10737418240 || plan.Expire != 1893456000 {
		t.Fatalf("unexpected first import: %+v", first)
	}
	first.Config.Selected = "B"
	first.Config.Rules = []engine.Rule{{Type: "domain", Value: "b.test", Via: "B"}, {Type: "match", Via: "DIRECT"}}

	nodes = "trojan://secret@a.example.test:443#A\ntrojan://secret@c.example.test:443#C"
	second, err := Import(context.Background(), strings.NewReader(server.URL), first.Config)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, node := range second.Config.Nodes {
		names = append(names, node.Name)
	}
	if strings.Join(names, ",") != "Manual,A,C" || len(second.Config.Subscriptions) != 1 ||
		second.Config.Selected != engine.Auto || second.Config.Rules[0].Via != "SELECT" {
		t.Fatalf("refresh did not replace subscription nodes: %v %+v", names, second.Config)
	}
}

func TestParseUserinfoIgnoresJunk(t *testing.T) {
	var plan engine.Subscription
	parseUserinfo("upload=1.5e3; download=; TOTAL=5000;expire=abc; extra=1", &plan)
	if plan.Upload != 1500 || plan.Download != 0 || plan.Total != 5000 || plan.Expire != 0 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}
