package engine

import (
	"context"
	"errors"
	"net"
	"testing"

	"mac-proxy/internal/backend"
)

func TestCloseDrainsDirectTCPAndUDP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	core, err := New(Default(), backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	address := listener.Addr().String()
	ctx := context.Background()
	tcp, err := core.Dial(ctx, "test", address)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := core.DialPacket(ctx, "test", address)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if got := core.Active(); got != 2 {
		t.Fatalf("expected two active connections, got %d", got)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := tcp.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("TCP connection survived core shutdown: %v", err)
	}
	if _, _, err := udp.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("UDP socket survived core shutdown: %v", err)
	}
	if got := core.Active(); got != 0 {
		t.Fatalf("expected no active connections, got %d", got)
	}
	if _, err := core.Dial(ctx, "test", address); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed core accepted a new dial: %v", err)
	}
}
