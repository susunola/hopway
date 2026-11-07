//go:build !hopway_native

package importer

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
)

func TestModernShareLinks(t *testing.T) {
	const uuid = "ccc641c2-e296-455c-9f8e-8d13a9b02976"
	legacySS := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pa:ss@example.test:8388"))
	links := strings.Join([]string{
		"vless://" + uuid + "@example.test:443?security=reality&sni=www.apple.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123abcd&flow=xtls-rprx-vision&type=tcp#Reality",
		"vless://" + uuid + "@example.test:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.test#WS",
		"trojan://secret@example.test:443?type=grpc&serviceName=svc&sni=example.test#gRPC",
		"hysteria2://secret@example.test:443?sni=example.test&obfs=salamander&obfs-password=x&mport=20000-30000#HY2",
		"tuic://" + uuid + ":secret@example.test:443?congestion_control=bbr&alpn=h3#TUIC",
		"ss://2022-blake3-aes-128-gcm:MDEyMzQ1Njc4OWFiY2RlZg%3D%3D@example.test:8388#SS2022",
		"ss://" + legacySS + "#Legacy",
		"anytls://secret@example.test:443?sni=example.test#AnyTLS",
		"trojan://secret@example.test:443?allowInsecure=1#Insecure",
	}, "\n")
	result, err := Import(context.Background(), strings.NewReader(links), engine.Default(), backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 8 || result.Skipped != 1 {
		t.Fatalf("added %d skipped %d: %v", result.Added, result.Skipped, result.Notes)
	}
	byName := map[string]string{}
	for _, node := range result.Config.Nodes {
		byName[node.Name] = string(node.Options)
	}
	for name, want := range map[string]string{
		"Reality": `"reality":{"enabled":true`, "WS": `"max_early_data":2048`, "gRPC": `"service_name":"svc"`,
		"HY2": `"server_ports":["20000:30000"]`, "TUIC": `"congestion_control":"bbr"`,
	} {
		if !strings.Contains(byName[name], want) {
			t.Errorf("%s options %s, want %s", name, byName[name], want)
		}
	}
	if !strings.Contains(byName["WS"], `"path":"/ws"`) {
		t.Errorf("early data not stripped from path: %s", byName["WS"])
	}
}

func TestClashGroupsAndRules(t *testing.T) {
	const profile = `
proxies:
  - {name: HK, type: trojan, server: hk.test, port: 443, password: x, network: ws, ws-opts: {path: /t, headers: {Host: cdn.test}}}
  - {name: JP, type: hysteria2, server: jp.test, port: 443, password: x, up: "50 Mbps"}
  - {name: SG, type: vless, server: sg.test, port: 443, uuid: ccc641c2-e296-455c-9f8e-8d13a9b02976, tls: true, reality-opts: {public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0}, client-fingerprint: chrome}
proxy-groups:
  - {name: Proxy, type: select, proxies: [Auto, HK, DIRECT]}
  - {name: Auto, type: url-test, proxies: [HK, JP, SG], url: "https://cp.cloudflare.com", interval: 600}
  - {name: Remote, type: select, use: [provider1]}
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-KEYWORD,ads,REJECT
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - DOMAIN,x.test,Remote
  - PROCESS-NAME,Telegram,DIRECT
  - MATCH,Proxy
`
	result, err := Import(context.Background(), strings.NewReader(profile), engine.Default(), backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	config := result.Config
	if len(config.Groups) != 2 || config.Selected != "Proxy" || config.Health == nil || config.Health.Interval != 600 {
		t.Fatalf("groups %+v health %+v selected %s", config.Groups, config.Health, config.Selected)
	}
	if len(config.Rules) != 6 || !config.Rules[2].NoResolve || config.Rules[3].Type != engine.RuleRuleSet ||
		config.Rules[4].Type != engine.RuleProcessName || config.Rules[5].Type != engine.RuleMatch || config.Rules[5].Via != "Proxy" {
		t.Fatalf("rules %+v", config.Rules)
	}
	core, err := engine.New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	core.Close()
}

func TestClashRuleProvidersAndGeo(t *testing.T) {
	const profile = `
proxies:
  - {name: HK, type: trojan, server: hk.test, port: 443, password: x}
proxy-groups:
  - {name: Proxy, type: select, proxies: [HK, DIRECT]}
rule-providers:
  reject: {type: http, behavior: domain, url: "https://example.test/reject.txt", interval: 86400}
  apple: {type: http, behavior: classical, format: yaml, url: "https://example.test/apple.yaml"}
  binary: {type: http, behavior: domain, format: mrs, url: "https://example.test/x.mrs"}
  local: {type: file, behavior: domain, path: ./x.yaml}
rules:
  - RULE-SET,reject,REJECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,binary,REJECT
  - RULE-SET,local,REJECT
  - GEOSITE,google,Proxy
  - GEOIP,LAN,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - GEOIP,cn,DIRECT
  - MATCH,Proxy
`
	result, err := Import(context.Background(), strings.NewReader(profile), engine.Default(), backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	sets := map[string]engine.RuleSet{}
	for _, set := range result.Config.RuleSets {
		sets[set.Name] = set
	}
	if len(sets) != 4 || sets["reject"].Format != "text" || sets["apple"].Format != "yaml" ||
		sets["geoip-cn"].URL != "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs" ||
		sets["geosite-google"].URL == "" {
		t.Fatalf("rule sets %+v", result.Config.RuleSets)
	}
	lan := 0
	for _, rule := range result.Config.Rules {
		if rule.Type == engine.RuleIPCIDR && rule.NoResolve {
			lan++
		}
	}
	// 4 rule-set rules + geosite + 12 LAN ranges + 2 geoip + match; mrs and file providers skipped.
	if lan != 12 || len(result.Config.Rules) != 2+1+12+2+1 {
		t.Fatalf("rules %+v", result.Config.Rules)
	}
	core, err := engine.New(result.Config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	core.Close()
}

func TestClashProviderAnnouncementsAndTransportCompatibility(t *testing.T) {
	const raw = `
proxies:
  - {name: "🌲 防失联网址：example.test", type: unsupported}
  - {name: "🌳 官网：example.test", type: unsupported}
  - {name: "🇭🇰 香港-09 | 流媒体（节点超时请更新）", type: trojan, server: hk.test, port: 443, password: fixture, network: grpc, grpc-opts: {grpc-service-name: media}, skip-cert-verify: true, alpn: [h2]}
  - {name: "🇭🇰 香港-10 | 流媒体", type: vless, server: hk.test, port: 443, uuid: ccc641c2-e296-455c-9f8e-8d13a9b02976, network: ws, tls: true, ws-opts: {path: /proxy, headers: {host: cdn.test, X-Example: media}, v2ray-http-upgrade: true}}
  - {name: Pinned, type: trojan, server: hk.test, port: 443, password: fixture, fingerprint: fixture}
`
	result, err := Import(context.Background(), strings.NewReader(raw), engine.Default(), backend.Default())
	if err != nil || result.Added != 2 || result.Announcements != 2 || result.Skipped != 3 {
		t.Fatalf("got %d added, %d announcements, %d skipped, %v", result.Added, result.Announcements, result.Skipped, err)
	}
	first, second := string(result.Config.Nodes[0].Options), string(result.Config.Nodes[1].Options)
	if !strings.Contains(first, `"type":"grpc"`) || !strings.Contains(first, `"alpn":["h2"]`) || strings.Contains(first, "insecure") {
		t.Fatalf("incorrect gRPC or TLS settings: %s", first)
	}
	for _, want := range []string{`"type":"httpupgrade"`, `"host":"cdn.test"`, `"X-Example":"media"`} {
		if !strings.Contains(second, want) {
			t.Fatalf("HTTP Upgrade settings %s, missing %s", second, want)
		}
	}
	if !strings.Contains(strings.Join(result.Notes, "\n"), "整张 TLS 证书指纹") {
		t.Fatal("expected an explicit explanation for the certificate fingerprint")
	}
}

func TestClashShadowTLSKeepsGroupAliasesAndTransport(t *testing.T) {
	const raw = `
proxies:
  - {name: HK, type: ss, server: hk.test, port: 443, cipher: aes-128-gcm, password: ss-fixture, udp: true, plugin: shadow-tls, plugin-opts: {host: cover.test, password: tls-fixture, version: 3}}
  - {name: HK alias, type: ss, server: hk.test, port: 443, cipher: aes-128-gcm, password: ss-fixture, udp: true, plugin: shadow-tls, plugin-opts: {host: cover.test, password: tls-fixture, version: 3}}
proxy-groups:
  - {name: Proxy, type: select, proxies: [HK alias]}
rules:
  - MATCH,Proxy
`
	result, err := Import(context.Background(), strings.NewReader(raw), engine.Default(), backend.Default())
	if err != nil || result.Added != 1 || result.Skipped != 1 {
		t.Fatalf("got %d added, %d skipped, %v", result.Added, result.Skipped, err)
	}
	node := result.Config.Nodes[0]
	if layer := node.ShadowTLS; layer == nil || layer.Version != 3 || layer.Host != "cover.test" ||
		layer.Password != "tls-fixture" || !layer.UDP || node.Password != "ss-fixture" {
		t.Fatal("ShadowTLS and Shadowsocks settings must remain separate")
	}
	if len(result.Config.Groups) != 1 || strings.Join(result.Config.Groups[0].Members, ",") != "HK" {
		t.Fatal("strategy group lost its duplicate node reference")
	}
	core, err := engine.New(result.Config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	core.Close()
}
