package importer

import (
	"encoding/csv"
	"errors"
	"net"
	"strings"

	"mac-proxy/internal/outbound"
)

// Surfboard and Surge both use a [Proxy] section for static outbounds.
func parseSurgeProfile(raw string, result *Result) bool {
	inProxy := false
	found := false
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inProxy = strings.EqualFold(line, "[Proxy]")
			found = found || inProxy
		} else if inProxy {
			name, fields, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			node, err := surgeNode(strings.TrimSpace(name), fields)
			result.add(node, err)
		}
	}
	return found
}

func surgeNode(name, fields string) (outbound.Node, error) {
	node := outbound.Node{Name: name}
	reader := csv.NewReader(strings.NewReader(fields))
	reader.TrimLeadingSpace = true
	items, err := reader.Read()
	if err != nil || len(items) < 3 {
		return node, errors.New("代理条目缺少协议、服务器或端口")
	}
	node.Type = strings.ToLower(strings.TrimSpace(items[0]))
	node.Server = net.JoinHostPort(strings.Trim(strings.TrimSpace(items[1]), "[]"), strings.TrimSpace(items[2]))
	var positional []string
	for _, option := range items[3:] {
		key, value, named := strings.Cut(option, "=")
		if !named {
			positional = append(positional, strings.TrimSpace(option))
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), "\"")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "username":
			node.Username = value
		case "password":
			node.Password = value
		case "encrypt-method", "cipher":
			node.Cipher = value
		case "sni":
			node.ServerName = value
		case "tls":
			node.TLS = value == "true" || value == "1"
		case "skip-cert-verify":
			if value != "false" && value != "0" {
				return node, errors.New("该节点要求关闭证书验证")
			}
		case "username-uuid":
			node.UUID = value
		case "tfo", "udp-relay", "test-url":
		default:
			return node, errors.New("代理条目使用了不支持的选项")
		}
	}
	if node.Type == "ss" {
		node.Type = "shadowsocks"
	}
	if node.Type == "http" && node.TLS {
		node.Type = "https"
	}
	if node.Type == "socks5" || node.Type == "http" || node.Type == "https" {
		if len(positional) == 2 && node.Username == "" && node.Password == "" {
			node.Username, node.Password = positional[0], positional[1]
			positional = nil
		}
	}
	if node.Type == "trojan" && len(positional) == 1 && node.Password == "" {
		node.Password, positional = positional[0], nil
	}
	if len(positional) != 0 || (node.Type == "socks5" && node.TLS) {
		return node, errors.New("代理条目的认证或 TLS 参数不受支持")
	}
	return node, nil
}
