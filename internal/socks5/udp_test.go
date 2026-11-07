package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/wire"
)

func openUDPAssociation(t *testing.T, dial DialPacketFunc) (*net.UDPConn, *net.UDPAddr) {
	t.Helper()
	loopback := net.IPv4(127, 0, 0, 1)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	served := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		served <- HandleWithUDP(conn, nil, dial)
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("association closed with %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("association did not release its workers")
		}
	})
	client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("SOCKS negotiation: %x, %v", greeting, err)
	}
	if _, err := client.Write([]byte{5, udpAssociate, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(client, response[:]); err != nil || response[1] != replySuccess {
		t.Fatalf("UDP ASSOCIATE: %x, %v", response, err)
	}
	address, err := wire.ReadAddress(client, response[3])
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	return udp, relay
}

func sendUDP(t *testing.T, client *net.UDPConn, relay *net.UDPAddr, target, payload string) {
	t.Helper()
	address, err := wire.EncodeAddress(target)
	if err != nil {
		t.Fatal(err)
	}
	datagram := append(append([]byte{0, 0, 0}, address...), payload...)
	if _, err := client.WriteToUDP(datagram, relay); err != nil {
		t.Fatal(err)
	}
}

func udpEcho(t *testing.T, label string) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		var buffer [128]byte
		for {
			n, from, err := conn.ReadFromUDP(buffer[:])
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(append([]byte(label), buffer[:n]...), from)
		}
	}()
	return conn.LocalAddr().String()
}

func awaitTarget(t *testing.T, queue <-chan string, want string) {
	t.Helper()
	select {
	case got := <-queue:
		if got != want {
			t.Fatalf("target %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
}

func TestUDPAssociationRoutesEachDestination(t *testing.T) {
	first, second := udpEcho(t, "first:"), udpEcho(t, "second:")
	blocked := udpEcho(t, "forbidden:")
	const slow = "127.0.0.1:1"
	started := make(chan string, 4)
	client, relay := openUDPAssociation(t, func(ctx context.Context, _ string, target string) (net.PacketConn, error) {
		started <- target
		switch target {
		case slow:
			<-ctx.Done()
			return nil, ctx.Err()
		case blocked:
			return nil, errors.New("route rejected")
		default:
			return backend.DirectPacket(ctx, target, nil)
		}
	})

	sendUDP(t, client, relay, slow, "blocked dial")
	awaitTarget(t, started, slow)
	sendUDP(t, client, relay, first, "a")
	awaitTarget(t, started, first)
	sendUDP(t, client, relay, blocked, "must not escape the rule")
	awaitTarget(t, started, blocked)
	sendUDP(t, client, relay, second, "b")
	awaitTarget(t, started, second)

	client.SetReadDeadline(time.Now().Add(time.Second))
	expected := map[string]string{first: "first:a", second: "second:b"}
	var buffer [128]byte
	for range 2 {
		n, _, err := client.ReadFromUDP(buffer[:])
		if err != nil {
			t.Fatal(err)
		}
		target, payload, err := parseDatagram(buffer[:n])
		if err != nil || expected[target] != string(payload) {
			t.Fatalf("unexpected reply from %q: %q, %v", target, payload, err)
		}
		delete(expected, target)
	}
	client.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if n, _, err := client.ReadFromUDP(buffer[:]); err == nil {
		t.Fatalf("unexpected reply after forwarding approved targets: %x", buffer[:n])
	}
}

func TestUDPAssociationReclaimsOldestSessionAtCapacity(t *testing.T) {
	started := make(chan string, maxUDPAssociationTargets+1)
	closed := make(chan string, maxUDPAssociationTargets+1)
	client, relay := openUDPAssociation(t, func(ctx context.Context, _ string, target string) (net.PacketConn, error) {
		started <- target
		<-ctx.Done()
		closed <- target
		return nil, ctx.Err()
	})
	target := func(i int) string { return "127.0.0.1:" + strconv.Itoa(10000+i) }
	for i := range maxUDPAssociationTargets {
		sendUDP(t, client, relay, target(i), "packet")
		awaitTarget(t, started, target(i))
	}
	select {
	case addr := <-closed:
		t.Fatalf("session %q retired before the table was full", addr)
	default:
	}
	sendUDP(t, client, relay, target(maxUDPAssociationTargets), "new target")
	awaitTarget(t, started, target(maxUDPAssociationTargets))
	awaitTarget(t, closed, target(0))
}
