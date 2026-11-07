package engine

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"mac-proxy/internal/outbound"
	"mac-proxy/internal/socks5"
)

// listen starts a TCP server on loopback and returns its address.
func listen(t *testing.T, serve func(*net.TCPConn)) string {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				serve(conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func socksNode(t *testing.T, name string) outbound.Node {
	address := listen(t, func(conn *net.TCPConn) {
		var dialer net.Dialer
		socks5.Handle(conn, func(ctx context.Context, _, target string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", target)
		})
	})
	return outbound.Node{Name: name, Type: "socks5", Server: address}
}

func deadNode(t *testing.T, name string) outbound.Node {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return outbound.Node{Name: name, Type: "socks5", Server: address}
}

func echo(t *testing.T) string {
	return listen(t, func(conn *net.TCPConn) { io.Copy(conn, conn) })
}

func autoConfig(nodes ...outbound.Node) Config {
	config := Default()
	config.Mode, config.Selected, config.Nodes = "global", Auto, nodes
	config.Rules = []Rule{{Type: "match", Via: "DIRECT"}}
	return config
}

func roundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "ping" {
		t.Fatalf("echo failed: %q %v", reply, err)
	}
}

func TestAutoFailsOverAndFallsBack(t *testing.T) {
	core, err := New(autoConfig(deadNode(t, "primary"), socksNode(t, "backup")))
	if err != nil {
		t.Fatal(err)
	}
	target := echo(t)
	conn, err := core.Dial(context.Background(), "socks5", target)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, conn)

	status := core.Status()
	if status.Auto != "backup" || status.Connections[0].Via != "backup" {
		t.Fatalf("expected failover to backup, got auto=%s via=%s", status.Auto, status.Connections[0].Via)
	}
	if health := nodeSummary(status, "primary").Health; health != "down" {
		t.Fatalf("primary should be marked down, got %q", health)
	}
	if usage := nodeSummary(status, "backup"); usage.Sent != 4 || usage.Recv != 4 {
		t.Fatalf("backup traffic not counted: %+v", usage)
	}

	// A health check that finds the primary working again moves AUTO back.
	core.mu.Lock()
	core.mark("primary", true, 30*time.Millisecond)
	core.mu.Unlock()
	if status := core.Status(); status.Auto != "primary" || nodeSummary(status, "primary").LatencyMS != 30 {
		t.Fatalf("AUTO did not fall back to primary: %+v", nodeSummary(status, "primary"))
	}
}

func TestAutoDoesNotBlameNodesForUnreachableTargets(t *testing.T) {
	core, err := New(autoConfig(socksNode(t, "one"), socksNode(t, "two")))
	if err != nil {
		t.Fatal(err)
	}
	unreachable := deadNode(t, "unused").Server
	if _, err := core.Dial(context.Background(), "socks5", unreachable); err == nil {
		t.Fatal("dial to a closed port unexpectedly succeeded")
	}
	status := core.Status()
	for _, name := range []string{"one", "two"} {
		if health := nodeSummary(status, name).Health; health == "down" {
			t.Fatalf("%s was marked down for a target failure", name)
		}
	}
}

func TestAutoSkipsSpentPlans(t *testing.T) {
	spent := socksNode(t, "spent")
	spent.Subscription = "old"
	fresh := socksNode(t, "fresh")
	fresh.Subscription = "new"
	config := autoConfig(spent, fresh)
	config.Subscriptions = []Subscription{
		{Name: "old", URL: "https://old.example/sub", Upload: 60, Download: 40, Total: 100},
		{Name: "new", URL: "https://new.example/sub", Expire: time.Now().Add(time.Hour).Unix()},
	}
	core, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if status := core.Status(); status.Auto != "fresh" || !nodeSummary(status, "spent").Spent {
		t.Fatalf("spent plan should be skipped: auto=%s", status.Auto)
	}
}

func TestReloadKeepsCountersAndPolicy(t *testing.T) {
	keep := socksNode(t, "keep")
	core, err := New(autoConfig(keep, socksNode(t, "drop")))
	if err != nil {
		t.Fatal(err)
	}
	if err := core.SetPolicy(Policy{Mode: "global", Selected: "keep"}); err != nil {
		t.Fatal(err)
	}
	conn, err := core.Dial(context.Background(), "http", echo(t))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, conn)
	if err := core.Reload(autoConfig(keep, socksNode(t, "added"))); err != nil {
		t.Fatal(err)
	}
	status := core.Status()
	if status.Policy.Selected != "keep" || status.Revision != 1 || nodeSummary(status, "keep").Sent != 4 {
		t.Fatalf("reload lost state: %+v", status)
	}
	if nodeSummary(status, "drop").Name != "" || nodeSummary(status, "added").Name != "added" {
		t.Fatal("reload did not swap nodes")
	}
}

func nodeSummary(status Status, name string) NodeSummary {
	for _, node := range status.Nodes {
		if node.Name == name {
			return node
		}
	}
	return NodeSummary{}
}

func TestProbeNeedsTwoFailuresAndDownNodesPreferRecentSuccess(t *testing.T) {
	core, err := New(autoConfig(socksNode(t, "first"), socksNode(t, "second")))
	if err != nil {
		t.Fatal(err)
	}
	core.mu.Lock()
	core.markProbe("first", false, 0)
	state := core.health["first"].state
	core.mu.Unlock()
	if state == "down" {
		t.Fatal("one failed probe took the node down")
	}
	core.mu.Lock()
	core.mark("second", true, 0)
	for _, name := range []string{"first", "second"} {
		core.markProbe(name, false, 0)
		core.markProbe(name, false, 0)
	}
	core.mu.Unlock()
	if status := core.Status(); status.Auto != "second" {
		t.Fatalf("with every node down AUTO should prefer the last working node, got %s", status.Auto)
	}
}
