package importer

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"mac-proxy/internal/outbound"
)

func parseLink(raw string) (outbound.Node, error) {
	scheme, body, ok := strings.Cut(raw, "://")
	if !ok {
		return outbound.Node{}, errors.New("节点链接格式无效")
	}
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "vmess":
		return parseVMess(body)
	case "ss", "vless", "trojan", "socks5", "socks", "hysteria2", "hy2", "tuic", "anytls":
	default:
		return outbound.Node{}, errors.New("节点协议不受支持")
	}
	if scheme == "ss" {
		raw = normalizeLegacySS(raw)
	}
	link, err := url.Parse(raw)
	if err != nil || link.Hostname() == "" || link.Port() == "" {
		return outbound.Node{}, errors.New("节点链接地址无效")
	}
	kind := map[string]string{"ss": "shadowsocks", "socks": "socks5", "hy2": "hysteria2"}[scheme]
	if kind == "" {
		kind = scheme
	}
	node := outbound.Node{Name: link.Fragment, Type: kind, Server: link.Host}
	if link.User == nil && kind != "socks5" {
		return node, errors.New("链接缺少认证信息")
	}
	query, err := url.ParseQuery(link.RawQuery)
	if err != nil {
		return node, errors.New("节点链接参数无效")
	}
	s := spec{
		network: query.Get("type"), path: query.Get("path"), host: query.Get("host"),
		serviceName: query.Get("serviceName"), security: query.Get("security"), sni: query.Get("sni"),
		fingerprint: query.Get("fp"), alpn: splitList(query.Get("alpn")), publicKey: query.Get("pbk"),
		shortID: query.Get("sid"), flow: query.Get("flow"),
		insecure: truthy(query.Get("allowInsecure")) || truthy(query.Get("insecure")), extra: map[string]any{},
	}
	if s.sni == "" {
		s.sni = query.Get("peer")
	}
	if header := query.Get("headerType"); header != "" && header != "none" {
		return node, errors.New("TCP 头部伪装不受支持")
	}
	if encryption := query.Get("encryption"); encryption != "" && encryption != "none" && kind == "vless" {
		return node, errors.New("VLESS 加密扩展不受支持")
	}
	var username, password string
	var hasPassword bool
	if link.User != nil {
		username = link.User.Username()
		password, hasPassword = link.User.Password()
	}
	switch kind {
	case "vless":
		if hasPassword {
			return node, errors.New("VLESS 链接的 UUID 无效")
		}
		node.UUID = username
	case "trojan", "anytls":
		if hasPassword {
			return node, errors.New("链接只能有一个密码")
		}
		node.Password = username
		if s.security == "" {
			s.security = "tls"
		}
		if s.security == "none" {
			return node, errors.New("此协议必须使用 TLS")
		}
	case "socks5":
		node.Username, node.Password = username, password
	case "hysteria2":
		node.Password = username
		if hasPassword {
			node.Password = username + ":" + password
		}
		s.network, s.security = "", "tls"
		if obfs := query.Get("obfs"); obfs != "" {
			if obfs != "salamander" {
				return node, errors.New("Hysteria2 混淆 " + obfs + " 不受支持")
			}
			s.extra["obfs"] = map[string]any{"type": "salamander", "password": query.Get("obfs-password")}
		}
		if ports := query.Get("mport"); ports != "" {
			s.extra["server_ports"] = hopPorts(ports)
		}
	case "tuic":
		node.UUID, node.Password = username, password
		s.network, s.security = "", "tls"
		if cc := query.Get("congestion_control"); cc != "" {
			s.extra["congestion_control"] = cc
		}
		if mode := query.Get("udp_relay_mode"); mode != "" {
			s.extra["udp_relay_mode"] = mode
		}
	case "shadowsocks":
		if hasPassword {
			node.Cipher, node.Password = username, password
		} else {
			decoded, err := decodeBase64(username)
			if err != nil {
				return node, err
			}
			node.Cipher, node.Password, _ = strings.Cut(string(decoded), ":")
		}
		if plugin := query.Get("plugin"); plugin != "" {
			name, opts, _ := strings.Cut(plugin, ";")
			switch name {
			case "obfs-local", "simple-obfs":
				name = "obfs-local"
			case "v2ray-plugin":
			default:
				return node, errors.New("Shadowsocks 插件 " + name + " 不受支持")
			}
			s.extra["plugin"], s.extra["plugin_opts"] = name, opts
		}
	}
	if err := s.apply(&node); err != nil {
		return node, err
	}
	return node, nil
}

// normalizeLegacySS converts ss://BASE64(method:pass@host:port)#name into the
// SIP002 form url.Parse understands.
func normalizeLegacySS(raw string) string {
	body := strings.TrimPrefix(raw, "ss://")
	fragment := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body, fragment = body[:i], body[i:]
	}
	if strings.Contains(body, "@") {
		return raw
	}
	main, query, _ := strings.Cut(body, "?")
	decoded, err := decodeBase64(main)
	if err != nil || !strings.Contains(string(decoded), "@") {
		return raw
	}
	at := strings.LastIndex(string(decoded), "@")
	userinfo, hostport := string(decoded[:at]), string(decoded[at+1:])
	method, password, _ := strings.Cut(userinfo, ":")
	result := "ss://" + url.PathEscape(method) + ":" + url.PathEscape(password) + "@" + hostport
	if query != "" {
		result += "?" + query
	}
	return result + fragment
}

// hopPorts turns "20000-30000,443" into sing-box server_ports ("20000:30000").
func hopPorts(value string) []string {
	var ports []string
	for _, part := range splitList(value) {
		ports = append(ports, strings.ReplaceAll(part, "-", ":"))
	}
	return ports
}

func parseVMess(body string) (outbound.Node, error) {
	decoded, err := decodeBase64(body)
	if err != nil {
		return outbound.Node{}, err
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &values); err != nil || values == nil {
		return outbound.Node{}, errors.New("VMess 分享链接无效")
	}
	field := func(key string) string {
		var value string
		if json.Unmarshal(values[key], &value) == nil {
			return value
		}
		return strings.Trim(string(values[key]), `"`)
	}
	node := outbound.Node{Name: field("ps"), Type: "vmess", UUID: field("id"), Cipher: field("scy")}
	if kind := field("type"); kind != "" && kind != "none" && field("net") != "grpc" {
		return node, errors.New("VMess 头部伪装不受支持")
	}
	if alterID := field("aid"); alterID != "" && alterID != "0" {
		return node, errors.New("只支持 VMess AEAD（alterId=0）")
	}
	port, err := strconv.ParseUint(field("port"), 10, 16)
	if err != nil || port == 0 {
		return node, errors.New("VMess 端口无效")
	}
	node.Server = net.JoinHostPort(strings.Trim(field("add"), "[]"), strconv.Itoa(int(port)))
	s := spec{network: field("net"), path: field("path"), host: field("host"), security: field("tls"),
		sni: field("sni"), fingerprint: field("fp"), alpn: splitList(field("alpn")),
		insecure: truthy(field("allowInsecure"))}
	if s.network == "grpc" {
		s.serviceName = s.path
	}
	if err := s.apply(&node); err != nil {
		return node, err
	}
	return node, nil
}
