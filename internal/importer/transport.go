package importer

import (
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"mac-proxy/internal/outbound"
)

// spec collects the transport and TLS settings shared by share links and
// Clash profiles, then renders them as sing-box outbound options.
type spec struct {
	network     string // tcp, ws, grpc, h2, httpupgrade
	path        string
	host        string
	serviceName string
	earlyData   int
	earlyHeader string
	security    string // "", tls, reality
	sni         string
	fingerprint string
	alpn        []string
	publicKey   string
	shortID     string
	flow        string
	insecure    bool
	extra       map[string]any // protocol-specific outbound fields
}

func (s *spec) apply(node *outbound.Node) error {
	if s.insecure {
		return errors.New("不导入跳过证书验证的节点")
	}
	options := map[string]any{}
	for key, value := range s.extra {
		options[key] = value
	}
	switch s.network {
	case "", "tcp", "raw":
	case "ws", "websocket":
		path := s.path
		transport := map[string]any{"type": "ws"}
		// Xray encodes early data as "?ed=2048" on the path.
		if parsed, err := url.Parse(path); err == nil && parsed.Query().Get("ed") != "" {
			if ed, err := strconv.Atoi(parsed.Query().Get("ed")); err == nil && ed > 0 {
				s.earlyData, s.earlyHeader = ed, "Sec-WebSocket-Protocol"
				query := parsed.Query()
				query.Del("ed")
				parsed.RawQuery = query.Encode()
				path = parsed.String()
			}
		}
		if path != "" {
			transport["path"] = path
		}
		if s.host != "" {
			transport["headers"] = map[string]any{"Host": s.host}
		}
		if s.earlyData > 0 {
			transport["max_early_data"] = s.earlyData
			header := s.earlyHeader
			if header == "" {
				header = "Sec-WebSocket-Protocol"
			}
			transport["early_data_header_name"] = header
		}
		options["transport"] = transport
	case "grpc", "gun":
		transport := map[string]any{"type": "grpc"}
		if s.serviceName != "" {
			transport["service_name"] = s.serviceName
		}
		options["transport"] = transport
	case "h2", "http":
		transport := map[string]any{"type": "http"}
		if s.path != "" {
			transport["path"] = s.path
		}
		if s.host != "" {
			transport["host"] = strings.Split(s.host, ",")
		}
		options["transport"] = transport
		if s.security == "" {
			s.security = "tls"
		}
	case "httpupgrade":
		transport := map[string]any{"type": "httpupgrade"}
		if s.path != "" {
			transport["path"] = s.path
		}
		if s.host != "" {
			transport["host"] = s.host
		}
		options["transport"] = transport
	default:
		return errors.New("传输方式 " + s.network + " 不受支持")
	}
	if s.flow != "" {
		if s.flow != "xtls-rprx-vision" || node.Type != "vless" {
			return errors.New("flow " + s.flow + " 不受支持")
		}
		options["flow"] = s.flow
	}
	switch s.security {
	case "", "none":
		if node.AlwaysTLS() {
			break
		}
		node.TLS = false
	case "tls", "xtls", "reality":
		node.TLS = true
	default:
		return errors.New("安全层 " + s.security + " 不受支持")
	}
	if node.Type == "shadowsocks" || node.Type == "socks5" {
		if node.TLS {
			return errors.New("此协议的 TLS 封装不受支持")
		}
	}
	if s.sni != "" {
		node.ServerName = s.sni
	}
	tls := map[string]any{}
	if len(s.alpn) != 0 {
		tls["alpn"] = s.alpn
	}
	if s.security == "reality" {
		if s.publicKey == "" {
			return errors.New("REALITY 缺少 public key")
		}
		reality := map[string]any{"enabled": true, "public_key": s.publicKey}
		if s.shortID != "" {
			reality["short_id"] = s.shortID
		}
		tls["reality"] = reality
		if s.fingerprint == "" {
			s.fingerprint = "chrome" // REALITY only works with a browser ClientHello
		}
	}
	if s.fingerprint != "" && s.fingerprint != "none" && node.UsesTLS() && node.Type != "hysteria2" && node.Type != "tuic" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": strings.ToLower(s.fingerprint)}
	}
	if len(tls) != 0 {
		if !node.UsesTLS() {
			return errors.New("TLS 参数需要启用 TLS")
		}
		options["tls"] = tls
	}
	if len(options) != 0 {
		data, err := json.Marshal(options)
		if err != nil {
			return err
		}
		node.Options = data
	}
	return nil
}

func splitList(value string) []string {
	var list []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list
}

func truthy(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "1" || value == "true" || value == "yes"
}
