package engine

import (
	"context"
	"io"
	"net"
	"slices"
	"testing"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/wire"
)

func TestAutoRoutingStaysStableAndFailsOver(t *testing.T) {
	switching, err := (AutoSwitchConfig{}).effective()
	if err != nil {
		t.Fatal(err)
	}
	state := autoState{
		config: &AutoConfig{Region: "HK", Groups: []AutoGroup{
			{Name: "Primary", Nodes: []string{"first", "second"}},
			{Name: "Backup", Nodes: []string{"backup"}},
		}},
		switching: switching, health: make(map[string]autoNode), activeGroup: -1,
	}
	apply := func(first, second, backup int64) {
		var results []ProbeResult
		for _, entry := range []struct {
			name string
			ms   int64
		}{{"first", first}, {"second", second}, {"backup", backup}} {
			result := ProbeResult{Name: entry.name, Milliseconds: entry.ms}
			if entry.ms == 0 {
				result.Failure = "timeout"
			}
			results = append(results, result)
		}
		state.apply(results)
	}
	expect := func(want string) {
		t.Helper()
		if state.activeNode != want {
			t.Fatalf("selected %q, want %q", state.activeNode, want)
		}
	}

	apply(210, 240, 40)
	expect("first") // Provider priority beats raw latency across providers.
	if !slices.Equal(state.orderedCandidates, []string{"first", "second", "backup"}) {
		t.Fatal("new connection retries must try the same provider before backup")
	}
	apply(700, 80, 40)
	expect("first")
	apply(700, 80, 40)
	expect("second")
	apply(0, 0, 40)
	expect("second")
	apply(0, 0, 40)
	expect("backup")
	apply(120, 130, 40)
	expect("backup")
	apply(120, 130, 40)
	expect("second") // The historical latency average favors the second node.
}

func TestAutoSwitchSettings(t *testing.T) {
	config := Default()
	config.AutoSwitch = AutoSwitchConfig{GainMS: 120, GainPercent: 40, Confirmations: 3, FailoverFailures: 3, RecoverySuccesses: 4}
	for _, name := range []string{"first", "second", "backup"} {
		config.Nodes = append(config.Nodes, outbound.Node{Name: name, Type: "socks5", Server: "127.0.0.1:1"})
	}
	// The validation engine does not start a probe monitor. This test supplies each round.
	core, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	policy := Policy{Mode: "auto", Selected: "DIRECT", Auto: &AutoConfig{
		Region: "HK", Groups: []AutoGroup{
			{Name: "Primary", Nodes: []string{"first", "second"}},
			{Name: "Backup", Nodes: []string{"backup"}},
		},
	}}
	if err := core.SetPolicy(policy); err != nil {
		t.Fatal(err)
	}
	state := core.auto
	probe := func(name string, ms int64) ProbeResult {
		result := ProbeResult{Name: name, Milliseconds: ms}
		if ms == 0 {
			result.Failure = "timeout"
		}
		return result
	}
	round := func(first, second int64) {
		state.apply([]ProbeResult{probe("first", first), probe("second", second), probe("backup", 35)})
	}
	expect := func(node string, wins int) {
		t.Helper()
		if state.activeNode != node || state.challengerWins != wins {
			t.Fatalf("active=%q wins=%d, want %q and %d", state.activeNode, state.challengerWins, node, wins)
		}
	}
	state.apply([]ProbeResult{probe("first", 200)})
	expect("first", 0)
	// 110 ms faster clears 40% but falls short of the absolute gate.
	for range 4 {
		round(200, 90)
	}
	expect("first", 0)
	if err := core.SetPolicy(policy); err != nil {
		t.Fatal(err)
	}
	state = core.auto
	state.apply([]ProbeResult{probe("first", 400)})
	// 150 ms faster clears the absolute gate but falls short of 40%.
	for range 4 {
		round(400, 250)
	}
	expect("first", 0)
	// The better node needs three usable rounds. A missing result is not a win.
	round(400, 10)
	expect("first", 1)
	state.apply([]ProbeResult{probe("first", 400), {Name: "second", Inconclusive: true}, probe("backup", 35)})
	expect("first", 1)
	round(400, 0)
	expect("first", 0)
	round(400, 10)
	expect("first", 1)
	round(400, 10)
	expect("first", 2)
	round(400, 10)
	expect("second", 0)
	for range 2 {
		round(0, 0)
		expect("second", 0)
	}
	round(0, 0)
	expect("backup", 0)
	for range 3 {
		round(400, 10)
		expect("backup", 0)
	}
	round(400, 10)
	expect("second", 0)
}

func TestAutoDialTriesBackup(t *testing.T) {
	backup, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := closed.Addr().String()
	closed.Close()
	config := Default()
	config.Nodes = append(config.Nodes, outbound.Node{Name: "first", Type: "socks5", Server: closedAddress}, outbound.Node{Name: "backup", Type: "socks5", Server: backup.Addr().String()})
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	if err := core.SetPolicy(Policy{Mode: "auto", Selected: "DIRECT", Auto: &AutoConfig{
		Region: "HK", Groups: []AutoGroup{{Name: "Primary", Nodes: []string{"first"}}, {Name: "Backup", Nodes: []string{"backup"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			peer, err := backup.Accept()
			if err != nil {
				return
			}
			go func() {
				defer peer.Close()
				var greeting [3]byte
				if _, err := io.ReadFull(peer, greeting[:]); err != nil {
					return
				}
				peer.Write([]byte{5, 0})
				var request [4]byte
				if _, err := io.ReadFull(peer, request[:]); err != nil {
					return
				}
				if _, err := wire.ReadAddress(peer, request[3]); err != nil {
					return
				}
				peer.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				<-done
			}()
		}
	}()

	conn, err := core.Dial(context.Background(), "fixture", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	connections := core.Status().Connections
	if len(connections) != 1 || connections[0].Via != "backup" {
		t.Fatalf("expected the backup node to carry the connection: %+v", connections)
	}
}

func TestAutoSwitchRecordsWhyTheRouteMoved(t *testing.T) {
	switching, err := (AutoSwitchConfig{}).effective()
	if err != nil {
		t.Fatal(err)
	}
	state := autoState{
		config: &AutoConfig{Region: "HK", Groups: []AutoGroup{
			{Name: "Primary", Nodes: []string{"first", "second"}},
			{Name: "Backup", Nodes: []string{"backup"}},
		}},
		switching: switching, health: make(map[string]autoNode), activeGroup: -1,
	}
	apply := func(first, second, backup int64) {
		t.Helper()
		var results []ProbeResult
		for _, entry := range []struct {
			name string
			ms   int64
		}{{"first", first}, {"second", second}, {"backup", backup}} {
			result := ProbeResult{Name: entry.name, Milliseconds: entry.ms}
			if entry.ms == 0 {
				result.Failure = "timeout"
			}
			results = append(results, result)
		}
		state.apply(results)
	}
	expect := func(reason, from, to string) {
		t.Helper()
		if state.activeNode != to {
			t.Fatalf("selected %q, want %q", state.activeNode, to)
		}
		if state.lastSwitch == nil {
			t.Fatal("automatic switch was not recorded")
		}
		if state.lastSwitch.Reason != reason || state.lastSwitch.From != from || state.lastSwitch.To != to {
			t.Fatalf("recorded %+v, want reason=%q %q -> %q", *state.lastSwitch, reason, from, to)
		}
		if state.lastSwitch.At == 0 {
			t.Fatal("switch has no timestamp")
		}
	}

	apply(210, 240, 40)
	expect("initial", "", "first")
	apply(400, 60, 40)
	apply(400, 60, 40)
	expect("latency", "first", "second")
	apply(0, 0, 40)
	apply(0, 0, 40)
	expect("provider", "second", "backup")
}
