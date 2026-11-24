package importer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/ruleset"
)

const MaxSize = 1 << 20

type Result struct {
	Config        engine.Config `json:"config"`
	Added         int           `json:"added"`
	Skipped       int           `json:"skipped"`
	Announcements int           `json:"announcements,omitempty"`
	incompatible  int
	Notes         []string                  `json:"notes"`
	Source        string                    `json:"-"`
	Validators    Validators                `json:"-"`
	NotModified   bool                      `json:"-"`
	Usage         *engine.SubscriptionUsage `json:"usage,omitempty"`
	names         map[string]bool
	seen          map[string]string
	renamed       map[string]string // original name -> final node name
	check         func(outbound.Node) error
}

type clash struct {
	Proxies       []yaml.Node              `yaml:"proxies"`
	Groups        []yaml.Node              `yaml:"proxy-groups"`
	Rules         []string                 `yaml:"rules"`
	RuleProviders map[string]clashProvider `yaml:"rule-providers"`
	Providers     yaml.Node                `yaml:"proxy-providers"`
}

type clashNode struct {
	UDP               bool `yaml:"udp"`
	UDPOverTCP        bool `yaml:"udp-over-tcp"`
	UDPOverTCPVersion int  `yaml:"udp-over-tcp-version"`

	Name                   string            `yaml:"name"`
	Type                   string            `yaml:"type"`
	Server                 string            `yaml:"server"`
	Port                   int               `yaml:"port"`
	Ports                  string            `yaml:"ports"`
	Username               string            `yaml:"username"`
	Password               string            `yaml:"password"`
	UUID                   string            `yaml:"uuid"`
	Cipher                 string            `yaml:"cipher"`
	SNI                    string            `yaml:"sni"`
	ServerName             string            `yaml:"servername"`
	Network                string            `yaml:"network"`
	Flow                   string            `yaml:"flow"`
	Plugin                 string            `yaml:"plugin"`
	PluginOpts             map[string]any    `yaml:"plugin-opts"`
	Dialer                 string            `yaml:"dialer-proxy"`
	Encryption             string            `yaml:"encryption"`
	TLS                    bool              `yaml:"tls"`
	Insecure               bool              `yaml:"skip-cert-verify"`
	AlterID                int               `yaml:"alterId"`
	Reality                *clashReality     `yaml:"reality-opts"`
	WS                     *clashWS          `yaml:"ws-opts"`
	GRPC                   map[string]string `yaml:"grpc-opts"`
	H2                     *clashH2          `yaml:"h2-opts"`
	HTTP                   yaml.Node         `yaml:"http-opts"`
	ALPN                   []string          `yaml:"alpn"`
	Fingerprint            string            `yaml:"client-fingerprint"`
	CertificateFingerprint string            `yaml:"fingerprint"`
	Obfs                   string            `yaml:"obfs"`
	ObfsPassword           string            `yaml:"obfs-password"`
	Congestion             string            `yaml:"congestion-controller"`
	UDPRelayMode           string            `yaml:"udp-relay-mode"`
	Up                     string            `yaml:"up"`
	Down                   string            `yaml:"down"`
}

type clashProvider struct {
	Type     string `yaml:"type"`
	Behavior string `yaml:"behavior"`
	Format   string `yaml:"format"`
	URL      string `yaml:"url"`
	Path     string `yaml:"path"`
	Interval int    `yaml:"interval"`
}

type clashReality struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

type clashWS struct {
	Path        string            `yaml:"path"`
	Headers     map[string]string `yaml:"headers"`
	EarlyData   int               `yaml:"max-early-data"`
	EarlyHeader string            `yaml:"early-data-header-name"`
	Upgrade     bool              `yaml:"v2ray-http-upgrade"`
}

type clashH2 struct {
	Host []string `yaml:"host"`
	Path string   `yaml:"path"`
}

type clashGroup struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	Proxies   []string `yaml:"proxies"`
	Use       []string `yaml:"use"`
	URL       string   `yaml:"url"`
	Interval  int      `yaml:"interval"`
	Tolerance int      `yaml:"tolerance"`
}

// unsupportedWireFields are Clash keys that change the framing or the
// handshake of a connection. Ignoring them would connect with a different
// protocol than the subscription describes, so the node is refused by name.
var unsupportedWireFields = map[string]string{
	"smux":                 "多路复用（smux）",
	"smux-opts":            "多路复用（smux）",
	"packet-encoding":      "Shadowsocks 2022 数据包编码",
	"xudp":                 "XUDP",
	"global-padding":       "全局填充",
	"authenticated-length": "认证长度头",
	"udp-over-tcp-version": "UDP over TCP 版本",
}

func wireFieldError(entry yaml.Node) string {
	var fields map[string]any
	if err := entry.Decode(&fields); err != nil {
		return ""
	}
	for key, meaning := range unsupportedWireFields {
		if value, present := fields[key]; present && fieldEnabled(value) {
			return "字段 " + key + "（" + meaning + "）会改变线路格式，当前不支持"
		}
	}
	return ""
}

// fieldEnabled treats an explicitly disabled option as absent, so a profile
// that writes smux: false still imports.
func fieldEnabled(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		typed = strings.TrimSpace(strings.ToLower(typed))
		return typed != "" && typed != "false" && typed != "none" && typed != "0"
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case float64:
		return typed != 0
	case map[string]any:
		return true
	case []any:
		return len(typed) != 0
	default:
		return true
	}
}

func (n clashNode) convert() (outbound.Node, error) {
	if n.UDPOverTCP && n.Plugin != "shadow-tls" && n.Plugin != "shadowtls" {
		return outbound.Node{}, errors.New("字段 udp-over-tcp（UDP over TCP）会改变线路格式，当前只支持 ShadowTLS 的封装")
	}
	if n.CertificateFingerprint != "" {
		return outbound.Node{}, errors.New("当前内核不支持 Clash 的整张 TLS 证书指纹校验")
	}
	if n.AlterID != 0 {
		return outbound.Node{}, errors.New("只支持 VMess AEAD（alterId=0）")
	}
	if n.HTTP.Kind != 0 || n.Network == "http" {
		return outbound.Node{}, errors.New("HTTP 头部伪装不受支持")
	}
	if n.Encryption != "" && n.Encryption != "none" {
		return outbound.Node{}, errors.New("VLESS 加密扩展不受支持")
	}
	if n.Port < 1 || n.Port > 65535 {
		return outbound.Node{}, errors.New("端口无效")
	}
	kind := strings.ToLower(n.Type)
	switch kind {
	case "ss":
		kind = "shadowsocks"
	case "socks", "socks5":
		kind = "socks5"
	case "hy2":
		kind = "hysteria2"
	}
	if n.TLS && kind == "http" {
		kind = "https"
	}
	node := outbound.Node{
		Name: n.Name, Type: kind, Server: net.JoinHostPort(strings.Trim(n.Server, "[]"), strconv.Itoa(n.Port)),
		Username: n.Username, Password: n.Password, UUID: n.UUID, Cipher: n.Cipher,
	}
	if !outbound.Types[kind] {
		return node, errors.New("节点协议 " + n.Type + " 不受支持")
	}
	s := spec{network: n.Network, sni: n.ServerName, alpn: n.ALPN, fingerprint: n.Fingerprint, flow: n.Flow,
		insecure: n.Insecure, extra: map[string]any{}}
	if s.sni == "" {
		s.sni = n.SNI
	}
	if n.TLS {
		s.security = "tls"
	}
	if n.Reality != nil {
		s.security, s.publicKey, s.shortID = "reality", n.Reality.PublicKey, n.Reality.ShortID
	}
	if n.WS != nil {
		s.path, s.earlyData, s.earlyHeader = n.WS.Path, n.WS.EarlyData, n.WS.EarlyHeader
		s.headers = make(map[string]string, len(n.WS.Headers))
		for name, value := range n.WS.Headers {
			if strings.EqualFold(name, "Host") {
				s.host = value
			} else {
				s.headers[name] = value
			}
		}
		if n.WS.Upgrade {
			if (n.Network != "ws" && n.Network != "websocket") || s.earlyData != 0 || s.earlyHeader != "" {
				return node, errors.New("此 HTTP Upgrade 与 WebSocket 提前数据的组合不受支持")
			}
			s.network = "httpupgrade"
		}
	}
	if n.GRPC != nil {
		s.serviceName = n.GRPC["grpc-service-name"]
	}
	if n.H2 != nil {
		s.path, s.host = n.H2.Path, strings.Join(n.H2.Host, ",")
	}
	if n.Dialer != "" {
		s.extra["detour"] = n.Dialer
	}
	switch kind {
	case "hysteria2":
		s.network, s.security = "", "tls"
		if n.Obfs != "" {
			if n.Obfs != "salamander" {
				return node, errors.New("Hysteria2 混淆 " + n.Obfs + " 不受支持")
			}
			s.extra["obfs"] = map[string]any{"type": "salamander", "password": n.ObfsPassword}
		}
		if n.Ports != "" {
			s.extra["server_ports"] = hopPorts(n.Ports)
		}
		for key, value := range map[string]string{"up_mbps": n.Up, "down_mbps": n.Down} {
			if mbps, err := strconv.Atoi(strings.Fields(value + " 0")[0]); err == nil && mbps > 0 {
				s.extra[key] = mbps
			}
		}
	case "tuic":
		s.network, s.security = "", "tls"
		if n.Congestion != "" {
			s.extra["congestion_control"] = n.Congestion
		}
		if n.UDPRelayMode != "" {
			s.extra["udp_relay_mode"] = n.UDPRelayMode
		}
	case "trojan", "anytls":
		s.security = map[bool]string{true: "reality", false: "tls"}[s.security == "reality"]
	case "shadowsocks":
		if n.Plugin == "shadow-tls" || n.Plugin == "shadowtls" {
			layer := &outbound.ShadowTLS{Version: 2, Fingerprint: n.Fingerprint, UDP: n.UDP}
			for key, value := range n.PluginOpts {
				switch key {
				case "host":
					layer.Host, _ = value.(string)
				case "password":
					layer.Password, _ = value.(string)
				case "version":
					switch version := value.(type) {
					case int:
						layer.Version = version
					case string:
						layer.Version, _ = strconv.Atoi(version)
					default:
						layer.Version = 0
					}
				case "alpn":
					list, ok := value.([]any)
					if !ok {
						return node, errors.New("ShadowTLS ALPN 格式无效")
					}
					for _, item := range list {
						protocol, ok := item.(string)
						if !ok || protocol == "" {
							return node, errors.New("ShadowTLS ALPN 格式无效")
						}
						layer.ALPN = append(layer.ALPN, protocol)
					}
				case "skip-cert-verify":
					if value != false {
						return node, errors.New("ShadowTLS 要求正常验证证书")
					}
				default:
					return node, fmt.Errorf("ShadowTLS 参数 %s 不受支持", key)
				}
			}
			if _, explicit := n.PluginOpts["alpn"]; !explicit {
				layer.ALPN = []string{"h2", "http/1.1"}
			}
			if n.UDP && n.UDPOverTCP {
				version := n.UDPOverTCPVersion
				if version == 0 {
					version = 1
				}
				if version != 1 && version != 2 {
					return node, errors.New("ShadowTLS UDP over TCP 版本不受支持")
				}
				s.extra["udp_over_tcp"] = map[string]any{"enabled": true, "version": version}
			}
			node.ShadowTLS = layer
			return node, s.apply(&node)
		}
		if n.Plugin != "" {
			name := n.Plugin
			if name == "obfs" {
				name = "obfs-local"
			}
			if name != "obfs-local" && name != "v2ray-plugin" {
				return node, errors.New("Shadowsocks 插件 " + n.Plugin + " 不受支持")
			}
			s.extra["plugin"], s.extra["plugin_opts"] = name, pluginOptions(n.PluginOpts)
		}
	}
	return node, s.apply(&node)
}

// pluginOptions renders Clash plugin-opts as the SIP003 "k=v;k=v" string.
func pluginOptions(options map[string]any) string {
	keys := make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys {
		value := fmt.Sprint(options[key])
		switch key {
		case "mode":
			if value == "http" || value == "tls" {
				key = "obfs"
			}
		case "tls":
			if value == "true" {
				parts = append(parts, "tls")
			}
			continue
		}
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, ";")
}

var errImportTooLarge = errors.New("导入内容超过 1 MB")

func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxSize+1))
	if err != nil {
		return nil, errors.New("读取导入内容失败")
	}
	if len(data) > MaxSize {
		return nil, errImportTooLarge
	}
	return data, nil
}

func importText(data []byte) (string, error) {
	if !utf8.Valid(data) {
		return "", errors.New("订阅或配置不是有效的 UTF-8 文本")
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(data)), "\ufeff")), nil
}

// Options adjust how Import fetches subscriptions.
type Options struct {
	// Transport carries subscription downloads; nil uses the default transport.
	Transport  http.RoundTripper
	Agent      string
	Validators Validators
}

func Import(ctx context.Context, input io.Reader, base engine.Config, impl backend.Backend) (Result, error) {
	return ImportWith(ctx, input, base, impl, Options{})
}

func ImportWith(ctx context.Context, input io.Reader, base engine.Config, impl backend.Backend, options Options) (Result, error) {
	data, err := readBounded(input)
	if err != nil {
		return Result{}, err
	}
	raw, err := importText(data)
	if err != nil {
		return Result{}, err
	}
	if raw == "" {
		return Result{}, errors.New("没有可导入的内容")
	}
	source, agent, _, err := SubscriptionLink(raw)
	if err != nil {
		return Result{}, err
	}
	var meter *engine.SubscriptionUsage
	var validators Validators
	if source != nil {
		if options.Agent == "" || options.Agent == "clash/HopWay" {
			options.Agent = agent
		}
		response, err := fetch(ctx, source, options)
		if err != nil {
			return Result{}, err
		}
		validators = response.validators
		if response.notModified {
			return Result{Source: source.String(), Validators: validators, NotModified: true}, nil
		}
		raw, err = importText(response.body)
		if err != nil {
			return Result{}, err
		}
		meter = readUsage(response.usage, raw)
	}
	if isHTMLDocument(raw) {
		return Result{}, errors.New("收到网页，无法作为订阅或节点配置导入")
	}
	if config, err := engine.Decode(strings.NewReader(raw)); strings.HasPrefix(raw, "{") && err == nil {
		if err := engine.ValidateContext(ctx, config, impl, nil); err != nil {
			return Result{}, fmt.Errorf("HopWay 配置无效：%w", err)
		}
		return Result{Config: config, Usage: meter, Added: len(config.Nodes), Notes: []string{"已导入完整 JSON 配置"}, Validators: validators}, nil
	}

	result := Result{Config: base, Usage: meter, Validators: validators, Notes: []string{}, names: map[string]bool{"DIRECT": true, "REJECT": true, "SELECT": true},
		seen: make(map[string]string), check: impl.Check, renamed: map[string]string{}}
	for _, node := range base.Nodes {
		result.names[node.Name] = true
		result.seen[identity(node)] = node.Name
	}
	for _, g := range base.Groups {
		result.names[g.Name] = true // shared links must not shadow existing groups
	}
	raw = stripSubscriptionHeader(raw)
	if decoded, err := decodeBase64(strings.Join(strings.Fields(raw), "")); err == nil && isLinks(stripSubscriptionHeader(string(decoded))) {
		raw, err = importText(decoded)
		if err != nil {
			return Result{}, err
		}
		raw = stripSubscriptionHeader(raw)
	}
	if isLinks(raw) {
		for _, line := range strings.Fields(raw) {
			var adjusted bool
			if source != nil {
				line, adjusted = verifyAnyTLSLink(line)
			}
			if adjusted {
				result.noteStrictTLS()
			}
			node, err := parseLink(line)
			if err == nil && node.Name == "" {
				node.Name, _ = url.PathUnescape(node.Name)
			}
			result.add(node, err)
		}
	} else if !parseSurgeProfile(raw, &result) {
		var profile clash
		decoder := yaml.NewDecoder(strings.NewReader(raw))
		if err := decoder.Decode(&profile); err != nil || decoder.Decode(new(yaml.Node)) != io.EOF {
			return Result{}, errors.New("无法识别内容。请复制订阅地址、节点链接或 Clash 配置")
		}
		for _, entry := range profile.Proxies {
			var proxy clashNode
			if err := entry.Decode(&proxy); err != nil {
				result.add(outbound.Node{}, errors.New("Clash 节点字段格式无效"))
				continue
			}
			if wireErr := wireFieldError(entry); wireErr != "" {
				result.add(outbound.Node{Name: proxy.Name}, errors.New(wireErr))
				continue
			}
			if proxy.Insecure {
				proxy.Insecure = false
				result.noteStrictTLS()
			}
			node, err := proxy.convert()
			node.Name = proxy.Name
			result.addNamed(proxy.Name, node, err)
		}
		var providerNodes map[string][]string
		if profile.Providers.Kind != 0 {
			var providers map[string]clashProvider
			if err := profile.Providers.Decode(&providers); err != nil {
				result.Notes = append(result.Notes, "远程节点集（proxy-providers）格式无效，已跳过")
			} else {
				providerNodes = result.importProviders(ctx, providers, options)
			}
		}
		if len(profile.Groups) != 0 {
			result.importClash(profile, providerNodes)
		}
	}
	if result.Announcements != 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("已跳过 %d 条服务商公告", result.Announcements))
	}
	if result.Added == 0 && result.Skipped == 0 {
		return Result{}, errors.New("没有找到可导入的节点。检查内联节点或远程节点集是否可访问")
	}
	if result.Added == 0 && result.Skipped > 0 {
		return Result{}, fmt.Errorf("没有新增节点，跳过 %d 项。%s", result.Skipped, strings.Join(result.Notes, "；"))
	}
	if len(base.Nodes) == 0 && len(result.Config.Nodes) != 0 && result.Config.Selected == "DIRECT" {
		result.Config.Selected = result.Config.Nodes[0].Name
		if len(result.Config.Groups) != 0 {
			result.Config.Selected = result.Config.Groups[0].Name
		}
	}
	if err := engine.ValidateContext(ctx, result.Config, impl, nil); err != nil {
		return Result{}, err
	}
	if source != nil {
		result.Source = source.String()
	}
	return result, nil
}

// importClash replaces groups and rules with the profile's, mapping names
// through any renames made while adding nodes.
func (result *Result) importClash(profile clash, providerNodes map[string][]string) {
	var groups []engine.Group
	declared := map[string]bool{}
	var parsed []clashGroup
	for _, entry := range profile.Groups {
		var g clashGroup
		if entry.Decode(&g) == nil && g.Name != "" {
			parsed = append(parsed, g)
			declared[g.Name] = true
		}
	}
	nodeNames := map[string]bool{"DIRECT": true, "REJECT": true, "SELECT": true}
	for _, node := range result.Config.Nodes {
		nodeNames[node.Name] = true
	}
	groupName := map[string]string{}
	taken := map[string]bool{}
	for _, g := range parsed {
		name := g.Name
		for i := 2; nodeNames[name] || taken[name]; i++ {
			name = fmt.Sprintf("%s (%d)", g.Name, i)
		}
		groupName[g.Name], taken[name] = name, true
	}
	resolve := func(member string) string {
		switch strings.ToUpper(member) {
		case "DIRECT":
			return "DIRECT"
		case "REJECT", "REJECT-DROP", "PASS":
			return "REJECT"
		}
		if name := groupName[member]; name != "" {
			return name
		}
		return result.renamed[member]
	}
	health := &engine.Health{}
	dropped := 0
	for _, g := range parsed {
		kind := g.Type
		switch kind {
		case "select", "url-test", "fallback":
		case "load-balance":
			kind = "url-test"
			result.Notes = append(result.Notes, "负载均衡组「"+g.Name+"」按最低延迟处理")
		default:
			dropped++
			continue
		}
		var members []string
		seen := map[string]bool{}
		for _, member := range g.Proxies {
			if name := resolve(member); name != "" && !seen[name] {
				members = append(members, name)
				seen[name] = true
			}
		}
		for _, provider := range g.Use {
			for _, name := range providerNodes[provider] {
				if !seen[name] {
					members = append(members, name)
					seen[name] = true
				}
			}
		}
		if len(members) == 0 {
			dropped++
			delete(groupName, g.Name)
			continue
		}
		if kind != "select" && health.URL == "" && g.URL != "" {
			health.URL, health.Interval = g.URL, max(g.Interval, 30)
		}
		groups = append(groups, engine.Group{Name: groupName[g.Name], Type: kind, Members: members, Tolerance: g.Tolerance})
	}
	// Dropping a group can empty another group that only pointed at it.
	for {
		valid := map[string]bool{}
		for _, g := range groups {
			valid[g.Name] = true
		}
		kept := groups[:0]
		for _, g := range groups {
			members := g.Members[:0:0]
			for _, member := range g.Members {
				if !taken[member] || valid[member] {
					members = append(members, member)
				}
			}
			g.Members = members
			if len(members) != 0 {
				kept = append(kept, g)
			} else {
				dropped++
			}
		}
		if len(kept) == len(groups) && len(valid) == len(kept) {
			groups = kept
			break
		}
		groups = kept
	}
	if dropped > 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("%d 个策略组无法导入", dropped))
	}
	sets := &ruleSetBuilder{providers: profile.RuleProviders}
	rules, skipped := convertRules(profile.Rules, func(target string) string {
		name := resolve(target)
		if name == "" || (taken[name] && !isGroupName(groups, name)) {
			return ""
		}
		return name
	}, sets)
	if skipped > 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("%d 条规则未导入（类型不支持，或指向的组不存在）", skipped))
	}
	if len(sets.list) != 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("已导入 %d 个规则集，首次启动后在后台下载", len(sets.list)))
	}
	result.Config.RuleSets = sets.list
	result.Config.Groups, result.Config.Rules = groups, rules
	if health.URL != "" {
		result.Config.Health = health
	}
	result.Config.Mode = "rule"
	result.Notes = append(result.Notes, fmt.Sprintf("已导入 %d 个策略组、%d 条规则，替换原有分组和规则", len(groups), len(rules)))
}

func isGroupName(groups []engine.Group, name string) bool {
	for _, g := range groups {
		if g.Name == name {
			return true
		}
	}
	return false
}

// Public GeoIP/GeoSite rule sets in sing-box binary format.
const (
	geoIPURL   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-%s.srs"
	geoSiteURL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-%s.srs"
)

// Private ranges, what Clash calls GEOIP,LAN.
var lanCIDRs = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}

type ruleSetBuilder struct {
	providers map[string]clashProvider
	list      []engine.RuleSet
	names     map[string]bool
}

// use returns the rule-set name for a provider or Geo code, adding it once.
func (b *ruleSetBuilder) use(kind, value string) string {
	if b.names == nil {
		b.names = map[string]bool{}
	}
	var set engine.RuleSet
	switch kind {
	case "GEOIP":
		code := strings.ToLower(value)
		set = engine.RuleSet{Name: "geoip-" + code, URL: fmt.Sprintf(geoIPURL, code)}
	case "GEOSITE":
		code := strings.ToLower(value)
		set = engine.RuleSet{Name: "geosite-" + code, URL: fmt.Sprintf(geoSiteURL, code)}
	case "RULE-SET":
		provider, ok := b.providers[value]
		if !ok || provider.Type != "http" || provider.URL == "" || provider.Format == "mrs" {
			return ""
		}
		format := provider.Format
		if format == "" {
			format = ruleset.DetectFormat(provider.URL)
			if format == ruleset.FormatText && !strings.HasSuffix(strings.ToLower(provider.URL), ".txt") {
				format = ruleset.FormatYAML // Clash's default
			}
		}
		set = engine.RuleSet{Name: value, URL: provider.URL, Format: format, Behavior: provider.Behavior}
		if provider.Interval >= 600 {
			set.Interval = provider.Interval
		}
	default:
		return ""
	}
	if !b.names[set.Name] {
		b.names[set.Name] = true
		b.list = append(b.list, set)
	}
	return set.Name
}

func convertRules(lines []string, target func(string) string, sets *ruleSetBuilder) ([]engine.Rule, int) {
	var rules []engine.Rule
	skipped := 0
	var final *engine.Rule
	for _, line := range lines {
		parts := strings.Split(line, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		kind := strings.ToUpper(parts[0])
		if kind == "MATCH" || kind == "FINAL" {
			if len(parts) >= 2 {
				if via := target(parts[1]); via != "" {
					final = &engine.Rule{Type: engine.RuleMatch, Via: via}
				}
			}
			break // nothing after MATCH can apply
		}
		if len(parts) < 3 {
			skipped++
			continue
		}
		via := target(parts[2])
		noResolve := false
		for _, option := range parts[3:] {
			if strings.EqualFold(option, "no-resolve") {
				noResolve = true
			}
		}
		if via == "" {
			skipped++
			continue
		}
		if kind == "GEOIP" && strings.EqualFold(parts[1], "LAN") {
			for _, cidr := range lanCIDRs {
				rules = append(rules, engine.Rule{Type: engine.RuleIPCIDR, Value: cidr, Via: via, NoResolve: noResolve})
			}
			continue
		}
		types := map[string]string{"DOMAIN": engine.RuleDomain, "DOMAIN-SUFFIX": engine.RuleDomainSuffix,
			"DOMAIN-KEYWORD": engine.RuleDomainKeyword, "IP-CIDR": engine.RuleIPCIDR, "IP-CIDR6": engine.RuleIPCIDR,
			"PROCESS-NAME": engine.RuleProcessName, "PROCESS-PATH": engine.RuleProcessPath,
			"PROCESS-BUNDLE-ID": engine.RuleProcessBundle}
		rule := engine.Rule{Type: types[kind], Value: parts[1], Via: via, NoResolve: noResolve}
		if rule.Type == "" && sets != nil {
			if name := sets.use(kind, parts[1]); name != "" {
				rule.Type, rule.Value = engine.RuleRuleSet, name
			}
		}
		if rule.Type == "" {
			skipped++
			continue
		}
		rules = append(rules, rule)
	}
	if final != nil {
		rules = append(rules, *final)
	}
	return rules, skipped
}

func isLinks(data string) bool {
	fields := strings.Fields(data)
	return len(fields) != 0 && strings.Contains(fields[0], "://")
}

func (result *Result) add(node outbound.Node, err error) {
	result.addNamed(node.Name, node, err)
}

func (result *Result) addNamed(original string, node outbound.Node, err error) {
	if subscriptionNotice(node.Name) {
		result.Skipped++
		result.Announcements++
		return
	}
	if err == nil {
		err = node.Validate()
	}
	if err == nil && result.check != nil {
		err = result.check(node)
	}
	if err != nil {
		result.Skipped++
		result.incompatible++
		if result.incompatible <= 4 {
			name := strings.TrimSpace(node.Name)
			if name == "" {
				name = fmt.Sprintf("第 %d 个不可导入项", result.Skipped)
			}
			runes := []rune(name)
			name = string(runes[:min(len(runes), 40)])
			result.Notes = append(result.Notes, fmt.Sprintf("%s：%s", name, err))
		}
		return
	}
	name := strings.TrimSpace(node.Name)
	if name == "" {
		name = node.Type + " · " + node.Server
	}
	key := identity(node)
	if existing := result.seen[key]; existing != "" {
		if _, exists := result.renamed[original]; original != "" && !exists {
			result.renamed[original] = existing
		}
		result.Skipped++
		if result.Skipped <= 4 {
			result.Notes = append(result.Notes, "已跳过重复节点："+name)
		}
		return
	}
	node.Name = name
	for i := 2; result.names[node.Name]; i++ {
		node.Name = fmt.Sprintf("%s (%d)", name, i)
	}
	result.names[node.Name] = true
	result.seen[key] = node.Name
	if _, exists := result.renamed[original]; original != "" && !exists {
		result.renamed[original] = node.Name // Clash resolves duplicates to the first
	}
	result.Config.Nodes = append(result.Config.Nodes, node)
	result.Added++
}

func identity(node outbound.Node) string {
	node.Name = ""
	data, _ := json.Marshal(node)
	return string(data)
}

func decodeBase64(raw string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if decoded, err := encoding.DecodeString(strings.TrimRight(raw, "=")); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("Base64 格式错误")
}
func stripSubscriptionHeader(raw string) string {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	for {
		line, rest, found := strings.Cut(raw, "\n")
		line = strings.TrimSpace(line)
		if !found || (!strings.HasPrefix(line, "STATUS=") && !strings.HasPrefix(line, "#")) {
			return raw
		}
		raw = strings.TrimSpace(rest)
	}
}

func subscriptionNotice(name string) bool {
	name = strings.TrimLeftFunc(name, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.Is(unicode.So, character) || character == '\uFE0F'
	})
	for _, prefix := range []string{
		"剩余流量", "剩餘流量", "套餐到期", "到期时间", "距离下次重置",
		"如果只显示当前节点", "请更新客户端", "轻语机场官网",
		"防失联网址：", "防失联网址:", "官网：", "官网:", "官方地址：", "官方地址:",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func verifyAnyTLSLink(raw string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(raw), "anytls://") {
		return raw, false
	}
	link, err := url.Parse(raw)
	if err != nil {
		return raw, false
	}
	query, err := url.ParseQuery(link.RawQuery)
	if err != nil || (!truthy(query.Get("allowInsecure")) && !truthy(query.Get("insecure"))) {
		return raw, false
	}
	query.Del("allowInsecure")
	query.Del("insecure")
	link.RawQuery = query.Encode()
	return link.String(), true
}

func (result *Result) noteStrictTLS() {
	const note = "要求跳过证书验证的节点将按正常 TLS 校验导入"
	for _, existing := range result.Notes {
		if existing == note {
			return
		}
	}
	result.Notes = append(result.Notes, note)
}
