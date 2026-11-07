package outbound

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
)

// UnmarshalJSON also reads the transport fields used by early HopWay builds.
func (node *Node) UnmarshalJSON(data []byte) error {
	type current Node
	var legacy struct {
		current
		ALPN    []string `json:"alpn"`
		Flow    string   `json:"flow"`
		Reality *struct {
			PublicKey   string `json:"publicKey"`
			ShortID     string `json:"shortId"`
			Fingerprint string `json:"fingerprint"`
		} `json:"reality"`
		WebSocket *struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
		} `json:"websocket"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&legacy); err != nil {
		return err
	}
	*node = Node(legacy.current)
	if len(legacy.ALPN) == 0 && legacy.Flow == "" && legacy.Reality == nil && legacy.WebSocket == nil {
		return nil
	}

	options := map[string]any{}
	if len(node.Options) != 0 {
		if err := json.Unmarshal(node.Options, &options); err != nil || options == nil {
			return errors.New("options must be a JSON object")
		}
	}
	if legacy.Flow != "" {
		if node.Type != "vless" || !node.TLS {
			return errors.New("VLESS flow requires TLS")
		}
		options["flow"] = legacy.Flow
	}
	if legacy.WebSocket != nil {
		options["transport"] = map[string]any{"type": "ws", "path": legacy.WebSocket.Path, "headers": legacy.WebSocket.Headers}
	}
	if len(legacy.ALPN) != 0 || legacy.Reality != nil {
		if !node.UsesTLS() {
			return errors.New("legacy TLS options require TLS")
		}
		tls := map[string]any{"enabled": true}
		if previous, ok := options["tls"].(map[string]any); ok {
			maps.Copy(tls, previous)
		}
		if len(legacy.ALPN) != 0 {
			tls["alpn"] = legacy.ALPN
		}
		if reality := legacy.Reality; reality != nil {
			fingerprint := reality.Fingerprint
			if fingerprint == "" {
				fingerprint = "chrome"
			}
			tls["reality"] = map[string]any{"enabled": true, "public_key": reality.PublicKey, "short_id": reality.ShortID}
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
		}
		options["tls"] = tls
	}
	var err error
	node.Options, err = json.Marshal(options)
	return err
}
