package outbound

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/wire"
)

// Node is one upstream proxy. The typed fields cover what every protocol
// shares; Options carries backend-specific settings (for sing-box: any
// outbound field such as transport, flow, reality, multiplex, obfs) and is
// merged over the fields generated from the typed ones.
type Node struct {
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Server     string          `json:"server"`
	Username   string          `json:"username,omitempty"`
	Password   string          `json:"password,omitempty"`
	ServerName string          `json:"serverName,omitempty"`
	Cipher     string          `json:"cipher,omitempty"`
	CAPEM      string          `json:"caPEM,omitempty"`
	UUID       string          `json:"uuid,omitempty"`
	TLS        bool            `json:"tls,omitempty"`
	Options    json.RawMessage `json:"options,omitempty"`
	ShadowTLS  *ShadowTLS      `json:"shadowTLS,omitempty"`

	rootCAs *x509.CertPool
	v2Dial  func(net.Conn, M.Socksaddr) (net.Conn, error)
}

// ShadowTLS wraps the TCP connection used by a Shadowsocks node.
type ShadowTLS struct {
	UDP         bool     `json:"udp,omitempty"`
	Version     int      `json:"version"`
	Host        string   `json:"host"`
	Password    string   `json:"password,omitempty"`
	Fingerprint string   `json:"clientFingerprint,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
}

// Types lists every node type HopWay understands. The native backend
// implements a subset; the sing-box backend implements all of them.
var Types = map[string]bool{
	"socks5": true, "http": true, "https": true, "shadowsocks": true, "trojan": true,
	"vless": true, "vmess": true, "hysteria2": true, "tuic": true, "anytls": true,
}

// AlwaysTLS reports protocols that cannot run without TLS.
func (node Node) AlwaysTLS() bool {
	switch node.Type {
	case "https", "trojan", "hysteria2", "tuic", "anytls":
		return true
	}
	return false
}

func (node Node) UsesTLS() bool {
	return node.AlwaysTLS() || ((node.Type == "vless" || node.Type == "vmess") && node.TLS)
}

// Validate performs checks that hold for every backend.
func (node Node) Validate() error {
	if !Types[node.Type] {
		return fmt.Errorf("unsupported node type %q", node.Type)
	}
	if _, _, err := wire.Split(node.Server); err != nil {
		return errors.New("server must be host:port")
	}
	if node.CAPEM != "" {
		if !node.UsesTLS() {
			return errors.New("caPEM requires TLS")
		}
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(node.CAPEM)) {
			return errors.New("caPEM must contain a valid PEM certificate")
		}
	}
	switch node.Type {
	case "socks5":
		if (node.Username == "") != (node.Password == "") || len(node.Username) > 255 || len(node.Password) > 255 {
			return errors.New("SOCKS5 credentials must both be present and at most 255 bytes")
		}
	case "http", "https":
		if node.Password != "" && node.Username == "" {
			return errors.New("HTTP proxy authentication requires a username")
		}
	case "trojan", "hysteria2", "anytls":
		if node.Password == "" {
			return fmt.Errorf("%s requires a password", node.Type)
		}
	case "shadowsocks":
		if node.Password == "" || node.Cipher == "" {
			return errors.New("Shadowsocks requires a password and a cipher")
		}
	case "vless", "vmess", "tuic":
		if !validUUID(node.UUID) {
			return fmt.Errorf("%s requires a valid UUID", node.Type)
		}
	}
	if layer := node.ShadowTLS; layer != nil {
		if node.Type != "shadowsocks" || node.TLS {
			return errors.New("ShadowTLS requires a Shadowsocks node without a separate TLS layer")
		}
		if layer.Host == "" || layer.Version < 1 || layer.Version > 3 || (layer.Version > 1 && layer.Password == "") {
			return errors.New("ShadowTLS requires a host, version 1–3 and a password for v2/v3")
		}
	}
	if len(node.Options) != 0 {
		var options map[string]any
		if err := json.Unmarshal(node.Options, &options); err != nil || options == nil {
			return errors.New("options must be a JSON object")
		}
		if err := rejectInsecure(options); err != nil {
			return err
		}
	}
	return nil
}

func validUUID(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

// rejectInsecure refuses option trees that turn off certificate checks. An
// unverified TLS hop lets anyone on the path read the traffic, which defeats
// the point of the proxy.
func rejectInsecure(value any) error {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "insecure" && child == true {
				return errors.New("nodes that skip certificate verification are not accepted")
			}
			if err := rejectInsecure(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := rejectInsecure(child); err != nil {
				return err
			}
		}
	}
	return nil
}
