package importer

import (
	"context"
	"strings"
	"testing"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
)

// A field that changes the wire format must not be dropped silently: the node
// would connect with a different protocol than the subscription describes.
func TestImportRefusesWireFieldsItCannotHonour(t *testing.T) {
	profile := `
proxies:
  - {name: muxed, type: socks5, server: a.example.test, port: 1080, smux: true}
  - {name: plain, type: socks5, server: b.example.test, port: 1080}
  - {name: uot, type: trojan, server: c.example.test, port: 443, password: p, udp-over-tcp: true}
`
	result, err := Import(context.Background(), strings.NewReader(profile), engine.Default(), backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 1 || len(result.Config.Nodes) != 1 || result.Config.Nodes[0].Name != "plain" {
		t.Fatalf("imported %d nodes (%+v), want only the plain one", result.Added, result.Config.Nodes)
	}
	var notes strings.Builder
	for _, note := range result.Notes {
		notes.WriteString(note)
		notes.WriteString("\n")
	}
	for _, want := range []string{"smux", "udp-over-tcp"} {
		if !strings.Contains(notes.String(), want) {
			t.Fatalf("skipped notes do not mention %q: %s", want, notes.String())
		}
	}
}
