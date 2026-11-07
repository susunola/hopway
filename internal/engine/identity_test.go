package engine

import (
	"encoding/json"
	"testing"

	"mac-proxy/internal/outbound"
)

func TestProbeKeysFollowRenamedDetourAndInvalidateOnChange(t *testing.T) {
	config := Default()
	config.Nodes = []outbound.Node{
		{Name: "Exit", Type: "socks5", Server: "127.0.0.1:1000", Options: json.RawMessage(`{"detour":"Entry"}`)},
		{Name: "Entry", Type: "socks5", Server: "127.0.0.1:1001"},
	}
	origin := SourceOutboundID("fixture", "Entry", false)
	config.OutboundIDs = map[string]string{"Entry": origin}
	before := config.ProbeKeys()
	config.Nodes[0].Options = json.RawMessage(`{"detour":"Entry (Fixture 2)"}`)
	config.Nodes[1].Name = "Entry (Fixture 2)"
	config.OutboundIDs = map[string]string{"Entry (Fixture 2)": origin}
	renamed := config.ProbeKeys()
	if before["Exit"] != renamed["Exit"] || before["Entry"] != renamed["Entry (Fixture 2)"] {
		t.Fatal("a display rename changed the identity of a probe")
	}
	config.Nodes[1].Password = "changed fixture credential"
	changed := config.ProbeKeys()
	if renamed["Exit"] == changed["Exit"] || renamed["Entry (Fixture 2)"] == changed["Entry (Fixture 2)"] {
		t.Fatal("a changed detour did not invalidate its own and dependent probes")
	}
}
