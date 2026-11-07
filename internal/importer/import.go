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
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
)

const MaxSize = 1 << 20

type Result struct {
	Config  engine.Config `json:"config"`
	Added   int           `json:"added"`
	Skipped int           `json:"skipped"`
	Notes   []string      `json:"notes"`
	names   map[string]bool
	seen    map[string]bool
}

type clash struct {
	Proxies   []yaml.Node `yaml:"proxies"`
	Groups    []yaml.Node `yaml:"proxy-groups"`
	Rules     []yaml.Node `yaml:"rules"`
	Providers yaml.Node   `yaml:"proxy-providers"`
}

type clashNode struct {
	Name        string    `yaml:"name"`
	Type        string    `yaml:"type"`
	Server      string    `yaml:"server"`
	Port        int       `yaml:"port"`
	Username    string    `yaml:"username"`
	Password    string    `yaml:"password"`
	UUID        string    `yaml:"uuid"`
	Cipher      string    `yaml:"cipher"`
	SNI         string    `yaml:"sni"`
	ServerName  string    `yaml:"servername"`
	Network     string    `yaml:"network"`
	Flow        string    `yaml:"flow"`
	Plugin      string    `yaml:"plugin"`
	Dialer      string    `yaml:"dialer-proxy"`
	Encryption  string    `yaml:"encryption"`
	TLS         bool      `yaml:"tls"`
	Insecure    bool      `yaml:"skip-cert-verify"`
	AlterID     int       `yaml:"alterId"`
	Reality     yaml.Node `yaml:"reality-opts"`
	WS          yaml.Node `yaml:"ws-opts"`
	GRPC        yaml.Node `yaml:"grpc-opts"`
	HTTP        yaml.Node `yaml:"http-opts"`
	ALPN        []string  `yaml:"alpn"`
	Fingerprint string    `yaml:"fingerprint"`
}

func (n clashNode) convert() (outbound.Node, error) {
	if (n.Network != "" && n.Network != "tcp") || n.Flow != "" || n.Plugin != "" ||
		n.Insecure || n.AlterID != 0 || n.Dialer != "" || (n.Encryption != "" && n.Encryption != "none") ||
		n.Reality.Kind != 0 || n.WS.Kind != 0 || n.GRPC.Kind != 0 || n.HTTP.Kind != 0 || len(n.ALPN) != 0 || n.Fingerprint != "" {
		return outbound.Node{}, errors.New("传输或 TLS 参数不受支持")
	}
	if n.Port < 1 || n.Port > 65535 {
		return outbound.Node{}, errors.New("端口无效")
	}
	kind := strings.ToLower(n.Type)
	if kind == "ss" {
		kind = "shadowsocks"
	}
	if n.TLS && kind == "http" {
		kind = "https"
	}
	if n.TLS && (kind == "socks5" || kind == "shadowsocks") {
		return outbound.Node{}, errors.New("此协议的 TLS 封装不受支持")
	}
	name := n.ServerName
	if name == "" {
		name = n.SNI
	}
	return outbound.Node{
		Name: n.Name, Type: kind, Server: net.JoinHostPort(strings.Trim(n.Server, "[]"), strconv.Itoa(n.Port)),
		Username: n.Username, Password: n.Password, UUID: n.UUID, Cipher: n.Cipher, ServerName: name, TLS: n.TLS,
	}, nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxSize+1))
	if err != nil {
		return nil, errors.New("读取导入内容失败")
	}
	if len(data) > MaxSize {
		return nil, errors.New("导入内容超过 1 MB")
	}
	return data, nil
}

func fetch(ctx context.Context, source *url.URL) ([]byte, error) {
	if source.User != nil || source.Hostname() == "" {
		return nil, errors.New("订阅地址无效")
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 || next.URL.User != nil ||
			(next.URL.Scheme != "https" && (next.URL.Scheme != "http" || via[len(via)-1].URL.Scheme == "https")) {
			return errors.New("invalid subscription redirect")
		}
		return nil
	}}
	request, err := http.NewRequestWithContext(ctx, "GET", source.String(), nil)
	if err != nil {
		return nil, errors.New("订阅地址无效")
	}
	request.Header.Set("User-Agent", "clash/HopWay")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("无法下载订阅，请检查网络和链接")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("订阅服务器返回 HTTP %d", response.StatusCode)
	}
	return readBounded(response.Body)
}

func Import(ctx context.Context, input io.Reader, base engine.Config) (Result, error) {
	data, err := readBounded(input)
	if err != nil {
		return Result{}, err
	}
	raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(data)), "\ufeff"))
	if raw == "" {
		return Result{}, errors.New("没有可导入的内容")
	}
	if !strings.ContainsAny(raw, " \r\n\t") {
		if source, err := url.Parse(raw); err == nil && (source.Scheme == "https" || source.Scheme == "http") {
			data, err := fetch(ctx, source)
			if err != nil {
				return Result{}, err
			}
			raw = strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
		}
	}
	if config, err := engine.Decode(strings.NewReader(raw)); strings.HasPrefix(raw, "{") && err == nil {
		if _, err := engine.New(config); err != nil {
			return Result{}, fmt.Errorf("HopWay 配置无效：%w", err)
		}
		return Result{Config: config, Added: len(config.Nodes), Notes: []string{"已导入完整 JSON 配置"}}, nil
	}

	result := Result{Config: base, Notes: []string{}, names: map[string]bool{"DIRECT": true, "REJECT": true, "SELECT": true}, seen: make(map[string]bool)}
	for _, node := range base.Nodes {
		result.names[node.Name] = true
		result.seen[identity(node)] = true
	}
	if decoded, err := decodeBase64(strings.Join(strings.Fields(raw), "")); err == nil && isLinks(string(decoded)) {
		raw = string(decoded)
	}
	if isLinks(raw) {
		for _, line := range strings.Fields(raw) {
			node, err := parseLink(line)
			result.add(node, err)
		}
	} else {
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
			node, err := proxy.convert()
			if err != nil {
				node.Name = proxy.Name
			}
			result.add(node, err)
		}
		if len(profile.Groups) != 0 || len(profile.Rules) != 0 || profile.Providers.Kind != 0 {
			result.Notes = append(result.Notes, "本次只导入内联节点，原有规则保持不变。Clash 策略组、规则和远程节点集未导入")
		}
	}
	if result.Added == 0 && result.Skipped == 0 {
		return Result{}, errors.New("没有找到内联节点。仅含远程 proxy-providers 的配置暂不支持")
	}
	if result.Added == 0 && result.Skipped > 0 {
		return Result{}, fmt.Errorf("没有新增节点，跳过 %d 项。%s", result.Skipped, strings.Join(result.Notes, "；"))
	}
	if len(base.Nodes) == 0 && len(result.Config.Nodes) != 0 && result.Config.Selected == "DIRECT" {
		result.Config.Selected = result.Config.Nodes[0].Name
	}
	if _, err := engine.New(result.Config); err != nil {
		return Result{}, err
	}
	return result, nil
}

func isLinks(data string) bool {
	fields := strings.Fields(data)
	return len(fields) != 0 && strings.Contains(fields[0], "://")
}

func (result *Result) add(node outbound.Node, err error) {
	if err == nil {
		err = node.Validate()
	}
	if err != nil {
		result.Skipped++
		if result.Skipped <= 4 {
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
	if result.seen[key] {
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
	result.seen[key] = true
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
