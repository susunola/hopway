package engine

import (
	"bytes"
	"encoding/json"
	"fmt"

	"mac-proxy/internal/outbound"
)

func validateNodeReferences(nodes []outbound.Node) error {
	known := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		known[node.Name] = true
	}
	detours := make(map[string]string)
	for _, node := range nodes {
		if len(node.Options) == 0 {
			continue
		}
		var links struct {
			Detour         string          `json:"detour"`
			DomainResolver json.RawMessage `json:"domain_resolver"`
		}
		if err := json.Unmarshal(node.Options, &links); err != nil {
			return fmt.Errorf("节点 %q 的出站选项无效: %w", node.Name, err)
		}
		// The profile has no named DNS server table. Empty values retain
		// HopWay's own resolver, and explicit tags would be unresolvable.
		if resolver := bytes.TrimSpace(links.DomainResolver); len(resolver) != 0 &&
			!bytes.Equal(resolver, []byte(`null`)) && !bytes.Equal(resolver, []byte(`""`)) {
			return fmt.Errorf("节点 %q 引用了未定义的 DNS 解析器 domain_resolver", node.Name)
		}
		if links.Detour != "" {
			if !known[links.Detour] {
				return fmt.Errorf("节点 %q 引用了不存在的前置节点 %q", node.Name, links.Detour)
			}
			detours[node.Name] = links.Detour
		}
	}
	// Each node has at most one outgoing edge. Mark completed walks so
	// every node is visited at most once without recursion.
	done := make(map[string]bool, len(detours))
	for _, node := range nodes {
		var chain []string
		for next := node.Name; detours[next] != "" && !done[next]; next = detours[next] {
			done[next] = true
			chain = append(chain, next)
		}
		if len(chain) > 0 {
			last := detours[chain[len(chain)-1]]
			for _, member := range chain {
				if last == member {
					return fmt.Errorf("节点 %q 的前置节点形成循环", member)
				}
			}
		}
	}
	return nil
}
