package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// SourceOutboundID identifies a node or group before subscription merging
// assigns it a display name.
func SourceOutboundID(provider, original string, group bool) string {
	kind := "node"
	if group {
		kind = "group"
	}
	return identityDigest(provider, original, kind)
}

func (config Config) OutboundID(name string, group bool) string {
	if id := config.OutboundIDs[name]; id != "" {
		return id
	}
	return SourceOutboundID("", name, group)
}

// ProbeKeys identifies measurements of the same node configuration and its
// detour chain. A display rename leaves the key intact.
func (config Config) ProbeKeys() map[string]string {
	type signature struct {
		base   string
		detour string
	}
	signatures := make(map[string]signature, len(config.Nodes))
	var target, fallback string
	if config.Health != nil {
		target, fallback = config.Health.URL, config.Health.FallbackURL
	}
	for _, node := range config.Nodes {
		name := node.Name
		node.Name = ""
		var detour string
		var options map[string]json.RawMessage
		if len(node.Options) != 0 && json.Unmarshal(node.Options, &options) == nil && options != nil {
			_ = json.Unmarshal(options["detour"], &detour)
			delete(options, "detour")
			if len(options) == 0 {
				node.Options = nil
			} else {
				node.Options, _ = json.Marshal(options)
			}
		}
		body, _ := json.Marshal(node)
		signatures[name] = signature{identityDigest(config.OutboundID(name, false), string(body), target, fallback), detour}
	}
	keys := make(map[string]string, len(signatures))
	for name := range signatures {
		var chain []string
		for next := name; signatures[next].base != "" && keys[next] == "" && len(chain) < len(signatures); next = signatures[next].detour {
			chain = append(chain, next)
		}
		for i := len(chain) - 1; i >= 0; i-- {
			member := chain[i]
			entry := signatures[member]
			keys[member] = identityDigest(entry.base, keys[entry.detour])
		}
	}
	return keys
}

func identityDigest(parts ...string) string {
	data, _ := json.Marshal(parts)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
