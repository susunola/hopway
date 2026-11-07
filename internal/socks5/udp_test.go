package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/wire"
)

func openUDPAssociation(t *testing.T, dial DialPacketFunc) (*net.UDPConn, *net.UDPAddr) {
	t.Helper()
	return openUDPAssociationWithIdle(t, dial, udpSessionIdle)
}

func openUDPAssociationWithIdle(t *testing.T, dial DialPacketFunc, idle time.Duration) (*net.UDPConn, *net.UDPAddr) {
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
		served <- HandleWithUDPTimeout(conn, nil, dial, idle)
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

type notifyUDPClosure struct {
	net.PacketConn
	closed chan<- struct{}
}

func (c notifyUDPClosure) Close() error {
	err := c.PacketConn.Close()
	c.closed <- struct{}{}
	return err
}

func TestUDPSessionKeepsOneWayTrafficAndReopensAfterIdle(t *testing.T) {
	const idle = 150 * time.Millisecond
	const interval = 30 * time.Millisecond
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	opened, closed := make(chan string, 12), make(chan struct{}, 12)
	client, relay := openUDPAssociationWithIdle(t, func(ctx context.Context, _, target string) (net.PacketConn, error) {
		conn, err := backend.DirectPacket(ctx, target, nil)
		if err != nil {
			return nil, err
		}
		opened <- target
		return notifyUDPClosure{conn, closed}, nil
	}, idle)
	target := origin.LocalAddr().String()
	send := func(payload string) {
		t.Helper()
		sendUDP(t, client, relay, target, payload)
		var buffer [32]byte
		origin.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := origin.ReadFromUDP(buffer[:])
		if err != nil || string(buffer[:n]) != payload {
			t.Fatalf("one-way UDP received %q, %v", buffer[:n], err)
		}
	}
	send("first")
	awaitTarget(t, opened, target)
	for n := range 8 {
		time.Sleep(interval)
		send(strconv.Itoa(n))
	}
	select {
	case <-opened:
		t.Fatal("one-way traffic recreated a session before it went idle")
	case <-closed:
		t.Fatal("one-way traffic did not keep the socket alive")
	default:
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle session did not close")
	}
	send("new session")
	awaitTarget(t, opened, target)
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

func TestUDPFragmentIsCountedAndAssociationContinues(t *testing.T) {
	target := udpEcho(t, "echo:")
	client, relay := openUDPAssociation(t, func(ctx context.Context, _, target string) (net.PacketConn, error) {
		return backend.DirectPacket(ctx, target, nil)
	})
	before := wire.SOCKSUDPDrops.Snapshot().Fragmented
	address, err := wire.EncodeAddress(target)
	if err != nil {
		t.Fatal(err)
	}
	fragment := append(append([]byte{0, 0, 1}, address...), []byte("ignore")...)
	if _, err := client.WriteToUDP(fragment, relay); err != nil {
		t.Fatal(err)
	}
	sendUDP(t, client, relay, target, "valid")
	client.SetReadDeadline(time.Now().Add(time.Second))
	var buffer [128]byte
	n, _, err := client.ReadFromUDP(buffer[:])
	if err != nil {
		t.Fatal(err)
	}
	from, payload, err := parseDatagram(buffer[:n])
	if err != nil || from != target || string(payload) != "echo:valid" {
		t.Fatalf("valid packet after a fragment returned %q, %q, %v", from, payload, err)
	}
	if got := wire.SOCKSUDPDrops.Snapshot().Fragmented; got != before+1 {
		t.Fatalf("fragment count = %d, want %d", got, before+1)
	}
}

func TestUDPDatagramAddresses(t *testing.T) {
	for _, sample := range []struct {
		header []byte
		target string
	}{
		{[]byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53}, "127.0.0.1:53"},
		{[]byte{0, 0, 0, 4, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187}, "[2001:db8::1]:443"},
		{[]byte{0, 0, 0, 3, 4, 't', 'e', 's', 't', 0, 53}, "test:53"},
	} {
		payload := []byte{0, 99, 0xff}
		datagram := append(sample.header, payload...)
		target, data, err := parseDatagram(datagram)
		if err != nil || target != sample.target || !slices.Equal(data, payload) {
			t.Fatalf("decoded %x as %q, %x, %v", datagram, target, data, err)
		}
	}
}

func TestUDPAssociationRelaysOutOfOrderAndDuplicateReplies(t *testing.T) {
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	target := origin.LocalAddr().String()
	client, relay := openUDPAssociation(t, func(ctx context.Context, _, target string) (net.PacketConn, error) {
		return backend.DirectPacket(ctx, target, nil)
	})
	sendUDP(t, client, relay, target, "first")
	sendUDP(t, client, relay, target, "second")
	var buffer [128]byte
	origin.SetDeadline(time.Now().Add(time.Second))
	var returnAddress *net.UDPAddr
	for range 2 {
		_, returnAddress, err = origin.ReadFromUDP(buffer[:])
		if err != nil {
			t.Fatal(err)
		}
	}
	replies := []string{"second", "first", "second", "third"}
	for _, reply := range replies {
		if _, err := origin.WriteToUDP([]byte(reply), returnAddress); err != nil {
			t.Fatal(err)
		}
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	var received []string
	for range replies {
		n, _, err := client.ReadFromUDP(buffer[:])
		if err != nil {
			t.Fatal(err)
		}
		from, payload, err := parseDatagram(buffer[:n])
		if err != nil || from != target {
			t.Fatalf("unexpected reply source %q: %v", from, err)
		}
		received = append(received, string(payload))
	}
	if !slices.Equal(received, replies) {
		t.Fatalf("replies = %v, want %v", received, replies)
	}
}

func TestSOCKSUDPQueuedBytesSharedAcrossSessions(t *testing.T) {
	before := udpQueuedBytes.Load()
	var sessions []*udpSession
	defer func() {
		for _, session := range sessions {
			session.discard(nil)
		}
		if got := udpQueuedBytes.Load(); got != before {
			t.Errorf("queue cleanup left %d charged bytes, started with %d", got, before)
		}
	}()
	payload := make([]byte, 65000)
	var rejected int
	for range 32 {
		session := &udpSession{queue: make(chan []byte, udpSendQueue)}
		sessions = append(sessions, session)
		for range udpSendQueue {
			if !session.enqueue(payload) {
				rejected++
			}
		}
	}
	if got := udpQueuedBytes.Load(); rejected == 0 || got > maxUDPQueuedBytes ||
		got+int64(len(payload)+udpQueueOverhead) <= maxUDPQueuedBytes {
		t.Fatalf("shared queue did not stop at its byte limit: charged=%d dropped=%d", got, rejected)
	}
}

func TestSOCKSUDPDropReasonsDistinguishCongestionAndUpstream(t *testing.T) {
	before := wire.SOCKSUDPDrops.Snapshot()
	waiting := make(chan struct{})
	fail := make(chan struct{})
	var started sync.Once
	client, relay := openUDPAssociation(t, func(ctx context.Context, _, target string) (net.PacketConn, error) {
		started.Do(func() { close(waiting) })
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-fail:
			return nil, errors.New("upstream fixture refused the session")
		}
	})
	target := "127.0.0.1:4321"
	sendUDP(t, client, relay, target, "first queued")
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("UDP dial did not start")
	}
	for range udpSendQueue * 2 {
		sendUDP(t, client, relay, target, "queued while opening")
	}
	deadline := time.Now().Add(time.Second)
	for wire.SOCKSUDPDrops.Snapshot().QueueFull == before.QueueFull {
		if time.Now().After(deadline) {
			t.Fatal("queue overflow was not counted")
		}
		time.Sleep(time.Millisecond)
	}
	close(fail)
	deadline = time.Now().Add(time.Second)
	for wire.SOCKSUDPDrops.Snapshot().Upstream == before.Upstream {
		if time.Now().After(deadline) {
			t.Fatal("upstream error did not account for the discarded packets")
		}
		time.Sleep(time.Millisecond)
	}
}
