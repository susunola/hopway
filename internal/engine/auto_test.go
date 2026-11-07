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
	state := autoState{
		config: &AutoConfig{Region: "HK", Groups: []AutoGroup{
			{Name: "Primary", Nodes: []string{"first", "second"}},
			{Name: "Backup", Nodes: []string{"backup"}},
		}},
		health: make(map[string]autoNode), activeGroup: -1,
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
