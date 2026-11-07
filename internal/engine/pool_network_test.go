//go:build !hopway_native

package engine

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/wire"
)

type countedRelay struct {
	addr   string
	opened atomic.Int32
	mu     sync.Mutex
	live   map[net.Conn]int32
}

func newCountedRelay(t *testing.T, upstream string) *countedRelay {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &countedRelay{addr: listener.Addr().String(), live: make(map[net.Conn]int32)}
	stopped := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(stopped)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			relay.mu.Lock()
			relay.live[client] = relay.opened.Add(1)
			relay.mu.Unlock()
			workers.Go(func() {
				defer func() {
					client.Close()
					relay.mu.Lock()
					delete(relay.live, client)
					relay.mu.Unlock()
				}()
				server, err := net.DialTimeout("tcp4", upstream, time.Second)
				if err == nil {
					wire.Relay(client, server)
				}
			})
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-stopped
		relay.closeSockets()
		workers.Wait()
	})
	return relay
}

func (r *countedRelay) closeSockets() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for client := range r.live {
		client.Close()
	}
}

func (r *countedRelay) closeSocket(id int32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for client, socket := range r.live {
		if socket == id {
			client.Close()
			return true
		}
	}
	return false
}

func (r *countedRelay) active() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.live)
}

func TestAnyTLSPoolsAreSeparateByNodeAndNetwork(t *testing.T) {
	fixture, nodes := startServer(t)
	one := nodes["anytls"]
	relay := newCountedRelay(t, one.Server)
	one.Name, one.Server = "one", relay.addr
	two := one
	two.Name = "two"
	config := Default()
	config.Nodes = []outbound.Node{one, two}
	core, err := New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	dialThrough := func(name string) net.Conn {
		t.Helper()
		if err := core.SetPolicy(Policy{Mode: "global", Selected: name}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := core.Dial(ctx, "fixture", fixture.echo)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	checkThrough := func(name string, want int32) {
		t.Helper()
		conn := dialThrough(name)
		defer conn.Close()
		roundTrip(t, conn, "check")
		if got := relay.opened.Load(); got != want {
			t.Fatalf("dial via %s: %d physical sessions, want %d", name, got, want)
		}
	}
	checkThrough("one", 1)
	checkThrough("one", 1)
	checkThrough("two", 2) // same server and credentials, separate outbound
	checkThrough("one", 2)

	core.NetworkChanged()
	deadline := time.Now().Add(time.Second)
	for relay.active() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active := relay.active(); active != 0 {
		t.Fatalf("network reset left %d old transports running", active)
	}
	checkThrough("one", 3)
	checkThrough("two", 4)

	// Drop the real transport on the relay side while a stream is open.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	active, err := core.Dial(ctx, "fixture", fixture.echo)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	active.SetDeadline(time.Now().Add(time.Second))
	if _, err := active.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var oneByte [1]byte
	if _, err := io.ReadFull(active, oneByte[:]); err != nil {
		t.Fatal(err)
	}
	if count := relay.opened.Load(); count != 4 {
		t.Fatalf("expected the stream to reuse its fourth physical session: %d", count)
	}
	survivor := dialThrough("one")
	defer survivor.Close()
	roundTrip(t, survivor, "before failure")
	if !relay.closeSocket(4) {
		t.Fatal("the second node's upstream session was missing")
	}
	if _, err := active.Read(oneByte[:]); err == nil {
		t.Fatal("closed upstream transport left its stream usable")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("stream did not notice that the upstream closed: %v", err)
	}
	active.Close()
	roundTrip(t, survivor, "other node keeps its original session")
	if sockets := relay.opened.Load(); sockets != 4 {
		t.Fatalf("the unaffected node replaced its transport: %d sockets", sockets)
	}
	checkThrough("two", 5)
	roundTrip(t, survivor, "after the failed node reconnects")
}
