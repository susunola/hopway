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
	switch scheme {
	case "vmess":
		return parseVMess(body)
	case "ss", "vless", "trojan", "socks5":
	default:
		return outbound.Node{}, errors.New("节点协议不受支持")
	}
	link, err := url.Parse(raw)
	if err != nil || link.Hostname() == "" {
		return outbound.Node{}, errors.New("节点链接地址无效")
	}
	node := outbound.Node{Name: link.Fragment, Type: scheme, Server: link.Host}
	if (link.User == nil && scheme != "socks5") || (link.Path != "" && link.Path != "/") {
		return node, errors.New("链接缺少认证信息或使用了额外传输路径")
	}
	query, err := url.ParseQuery(link.RawQuery)
	if err != nil {
		return node, errors.New("节点链接参数无效")
	}
	for key := range query {
		switch key {
		case "type", "security", "sni", "encryption", "flow", "allowInsecure", "plugin", "headerType":
		default:
			return node, errors.New("链接包含不支持的传输参数")
		}
	}
	if transport := query.Get("type"); transport != "" && transport != "tcp" && transport != "raw" {
		return node, errors.New("目前只支持 TCP 传输")
	}
	if header := query.Get("headerType"); header != "" && header != "none" {
		return node, errors.New("此 TCP 头部封装不受支持")
	}
	if security := query.Get("security"); security != "" && security != "none" && security != "tls" {
		return node, errors.New("目前只支持标准 TLS")
	}
	if flow := query.Get("flow"); flow != "" {
		return node, errors.New("此 flow（例如 Vision）不受支持")
	}
	if encryption := query.Get("encryption"); encryption != "" && encryption != "none" {
		return node, errors.New("此加密扩展不受支持")
	}
	if insecure := query.Get("allowInsecure"); insecure != "" && insecure != "0" && insecure != "false" {
		return node, errors.New("不导入跳过证书验证的节点")
	}
	if query.Get("plugin") != "" {
		return node, errors.New("暂不支持插件节点")
	}
	node.ServerName = query.Get("sni")
	node.TLS = query.Get("security") == "tls"
	username := link.User.Username()
	password, hasPassword := link.User.Password()
	switch scheme {
	case "vless":
		if hasPassword {
			return node, errors.New("VLESS 链接的 UUID 无效")
		}
		node.UUID = username
	case "trojan":
		if hasPassword || query.Get("security") == "none" {
			return node, errors.New("Trojan 链接必须使用 TLS 和单个密码")
		}
		node.Password = username
	case "socks5":
		if node.TLS {
			return node, errors.New("暂不支持 SOCKS5 的 TLS 封装")
		}
		node.Username, node.Password = username, password
	case "ss":
		if node.TLS {
			return node, errors.New("暂不支持 Shadowsocks 的 TLS 封装")
		}
		node.Type = "shadowsocks"
		if hasPassword {
			node.Cipher, node.Password = username, password
		} else {
			decoded, err := decodeBase64(username)
			if err != nil {
				return node, err
			}
			node.Cipher, node.Password, _ = strings.Cut(string(decoded), ":")
		}
	}
	return node, nil
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
		return string(values[key])
	}
	node := outbound.Node{Name: field("ps"), Type: "vmess", UUID: field("id"), Cipher: field("scy"),
		ServerName: field("sni"), TLS: field("tls") == "tls"}
	if transport := field("net"); transport != "" && transport != "tcp" && transport != "raw" {
		return node, errors.New("目前只支持 TCP 传输")
	}
	if kind := field("type"); kind != "" && kind != "none" {
		return node, errors.New("此 VMess 传输封装不受支持")
	}
	if alterID := field("aid"); alterID != "" && alterID != "0" {
		return node, errors.New("只支持 VMess AEAD（alterId=0）")
	}
	if tls := field("tls"); tls != "" && tls != "none" && tls != "tls" {
		return node, errors.New("目前只支持标准 TLS")
	}
	for _, key := range []string{"alpn", "fp", "allowInsecure"} {
		if value := field(key); value != "" && value != "0" && value != "false" {
			return node, errors.New("此 VMess TLS 参数不受支持")
		}
	}
	port, err := strconv.ParseUint(field("port"), 10, 16)
	if err != nil || port == 0 {
		return node, errors.New("VMess 端口无效")
	}
	node.Server = net.JoinHostPort(strings.Trim(field("add"), "[]"), strconv.Itoa(int(port)))
	return node, nil
}
