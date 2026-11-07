package importer

import (
	"errors"
	"net/url"
	"strings"
)

// subscription extracts the download URL and the client format requested by
// the original import link. A nil URL means the input is a profile or node.
func SubscriptionLink(raw string) (*url.URL, string, string, error) {
	const defaultAgent = "Clash.Meta/HopWay"
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "clash://"):
		link, err := url.Parse(raw)
		if err != nil || !strings.EqualFold(link.Host, "install-config") || link.User != nil || (link.Path != "" && link.Path != "/") {
			return nil, "", "", errors.New("Clash 一键导入链接无效")
		}
		params, err := url.ParseQuery(link.RawQuery)
		if err != nil || len(params["url"]) != 1 {
			return nil, "", "", errors.New("Clash 一键导入链接需要一个订阅地址")
		}
		source, agent, err := subscriptionURL(params.Get("url"), "Clash.Meta/HopWay")
		return source, agent, params.Get("name"), err
	case strings.HasPrefix(lower, "v2rayng://"),
		strings.HasPrefix(lower, "surge://"), strings.HasPrefix(lower, "surge3://"), strings.HasPrefix(lower, "surfboard://"):
		link, err := url.Parse(raw)
		if err != nil || link.User != nil {
			return nil, "", "", errors.New("一键导入链接无效")
		}
		action := link.Host + strings.Trim(link.Path, "/")
		agent := "Surge"
		expected := "install-config"
		if link.Scheme == "v2rayng" {
			agent, expected = "v2rayNG", "install-sub"
		}
		params, err := url.ParseQuery(link.RawQuery)
		if action != expected || err != nil || len(params["url"]) != 1 {
			return nil, "", "", errors.New("一键导入链接需要一个订阅地址")
		}
		source, agent, err := subscriptionURL(params.Get("url"), agent)
		return source, agent, params.Get("name"), err
	case strings.HasPrefix(lower, "shadowrocket://"), strings.HasPrefix(lower, "sub://"):
		const prefix = "shadowrocket://add/"
		payload := raw
		if strings.HasPrefix(lower, prefix) {
			payload = raw[len(prefix):]
		}
		const sub = "sub://"
		if !strings.HasPrefix(strings.ToLower(payload), sub) {
			return nil, "", "", errors.New("Shadowrocket 一键导入链接需要 sub:// 订阅内容")
		}
		encoded := payload[len(sub):]
		var name string
		if index := strings.IndexAny(encoded, "?#"); index >= 0 {
			options := encoded[index:]
			if strings.HasPrefix(options, "?") {
				query, _, _ := strings.Cut(options[1:], "#")
				values, _ := url.ParseQuery(query)
				name = values.Get("remark")
			}
			encoded = encoded[:index]
		}
		encoded, err := url.PathUnescape(encoded)
		if err != nil {
			return nil, "", "", errors.New("Shadowrocket 订阅编码无效")
		}
		decoded, err := decodeBase64(encoded)
		if err != nil {
			return nil, "", "", errors.New("Shadowrocket 订阅编码无效")
		}
		source, agent, err := subscriptionURL(string(decoded), "Shadowrocket")
		return source, agent, name, err
	case !strings.ContainsAny(raw, " \r\n\t") &&
		(strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://")):
		source, agent, err := subscriptionURL(raw, defaultAgent)
		return source, agent, "", err
	default:
		return nil, "", "", nil
	}
}

func subscriptionURL(raw, agent string) (*url.URL, string, error) {
	source, err := url.Parse(raw)
	if agent == "" || agent == "clash/HopWay" {
		agent = "Clash.Meta/HopWay"
	}
	if err == nil {
		source.Fragment = ""
	}
	if err != nil || (source.Scheme != "http" && source.Scheme != "https") ||
		source.Hostname() == "" || source.User != nil {
		return nil, "", errors.New("订阅地址必须是有效的 HTTP 或 HTTPS 链接")
	}
	return source, agent, nil
}
