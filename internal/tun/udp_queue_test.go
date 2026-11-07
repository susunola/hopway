//go:build (darwin || linux) && !hopway_native

package tun

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	stun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"mac-proxy/internal/wire"
)

type queueFixtureHandler chan N.PacketConn

func (h queueFixtureHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	h <- conn
}

func TestUDPQueueReleasesAllNATReadAndDiscardPaths(t *testing.T) {
	handler := make(queueFixtureHandler, 2)
	var drops int
	nat := stun.NewUDPNat(stun.UDPNatOptions{
		Handler: handler, Timeout: time.Minute, MaxSize: 1, Shared: true,
		QueueBudget: &wire.UDPQueue, OnQueueDrop: func() { drops++ },
		Prepare: func(_, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.Background(), nil, nil
		},
	})
	if err := nat.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		nat.Close()
		if used := wire.UDPQueue.Bytes(); used != 0 {
			t.Errorf("NAT close left %d bytes queued", used)
		}
	})
	waitConn := func() N.PacketConn {
		t.Helper()
		select {
		case conn := <-handler:
			return conn
		case <-time.After(time.Second):
			t.Fatal("UDP connection handler did not start")
			return nil
		}
	}
	checkUsed := func(want int64) {
		t.Helper()
		if used := wire.UDPQueue.Bytes(); used != want {
			t.Fatalf("UDP queue charged %d bytes, want %d", used, want)
		}
	}
	source := M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 3030}
	target := M.Socksaddr{Addr: netip.MustParseAddr("203.0.113.1"), Port: 5050}
	payload := bytes.Repeat([]byte{0x6b}, 64)
	send := func() { nat.NewPacket([][]byte{payload[:31], payload[31:]}, source, target, nil) }
	send()
	conn := waitConn()
	const small = 128 + 64
	const withHeadroom = 128 + 128
	checkUsed(small)
	read := buf.NewSize(len(payload))
	defer read.Release()
	if got, err := conn.ReadPacket(read); err != nil || got != target || !bytes.Equal(read.Bytes(), payload) {
		t.Fatalf("NAT read: %s, %x, %v", got, read.Bytes(), err)
	}
	checkUsed(0)
	batchReader := conn.(N.PacketBatchReadWaiter)
	batchReader.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 1, RearHeadroom: 1, BatchSize: 2})
	// There is space for the payload reservation but no space for headroom.
	const otherQueues = wire.UDPQueueLimit - small
	if !wire.UDPQueue.TryReserve(otherQueues) {
		t.Fatal("could not simulate full queues")
	}
	send()
	used := wire.UDPQueue.Bytes()
	wire.UDPQueue.Release(otherQueues)
	if drops != 1 || used != otherQueues {
		t.Fatalf("headroom rejection leaked a reservation: drops=%d, used=%d", drops, used)
	}
	batch := []*buf.Buffer{buf.As(bytes.Clone(payload)), buf.As(bytes.Clone(payload))}
	nat.NewPacketBatch(batch, []M.Socksaddr{source, source}, target, nil)
	checkUsed(2 * withHeadroom)
	packets, targets, err := batchReader.WaitReadPackets()
	if err != nil || len(packets) != 2 {
		t.Fatalf("NAT batch read: %d packets, %v", len(packets), err)
	}
	for i, packet := range packets {
		if targets[i] != target || !bytes.Equal(packet.Bytes(), payload) || packet.Start() < 1 {
			t.Errorf("NAT batch packet %d lost its content or headroom", i)
		}
		packet.Release()
	}
	checkUsed(0)
	send()
	checkUsed(withHeadroom)
	// A new source evicts the old flow and releases its unread datagram.
	source.Port++
	send()
	conn = waitConn()
	checkUsed(small)
	send()
	if discarded := conn.(interface{ CloseAndDiscardQueued() int }).CloseAndDiscardQueued(); discarded != 2 {
		t.Fatalf("discarded %d datagrams, want 2", discarded)
	}
	checkUsed(0)
	source.Port++
	send()
	waitConn()
	checkUsed(small)
	nat.Purge()
	checkUsed(0)
	source.Port++
	send()
	conn = waitConn()
	checkUsed(small)
	if !conn.(interface{ SetTimeout(time.Duration) bool }).SetTimeout(15 * time.Millisecond) {
		t.Fatal("failed to expire the queued flow")
	}
	deadline := time.Now().Add(time.Second)
	for wire.UDPQueue.Bytes() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	checkUsed(0)
	source.Port++
	send()
	waitConn()
	checkUsed(small) // The test cleanup verifies NAT close releases this last packet.
}
