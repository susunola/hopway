//go:build !hopway_native && (darwin || linux)

package tun

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	stun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type udpRetirementFlow struct {
	ctx  context.Context
	conn N.PacketConn
}

type udpRetirementHandler chan udpRetirementFlow

func (h udpRetirementHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	h <- udpRetirementFlow{ctx: ctx, conn: conn}
}

type udpRetirementWriter struct {
	admitted chan struct{}
	release  <-chan struct{}
	written  chan string
}

func (w *udpRetirementWriter) WritePacket(packet *buf.Buffer, _ M.Socksaddr) error {
	defer packet.Release()
	payload := string(packet.Bytes())
	if payload == "admitted before expiry" {
		close(w.admitted)
		<-w.release
	}
	w.written <- payload
	return nil
}

func (w *udpRetirementWriter) WritePacketBatch(packets []*buf.Buffer, targets []M.Socksaddr) error {
	for i, packet := range packets {
		_ = w.WritePacket(packet, targets[i])
	}
	return nil
}

func TestNATExpirationFencesOldPacketAndBatchWriters(t *testing.T) {
	handler := make(udpRetirementHandler, 3)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	writer := &udpRetirementWriter{
		admitted: make(chan struct{}), release: release, written: make(chan string, 8),
	}
	nat := stun.NewUDPNat(stun.UDPNatOptions{Handler: handler, Timeout: time.Minute,
		Prepare: func(_, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.Background(), writer, nil
		},
	})
	if err := nat.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nat.Close() })
	source := M.ParseSocksaddr("192.0.2.1:3000")
	target := M.ParseSocksaddr("203.0.113.1:4000")
	open := func() udpRetirementFlow {
		t.Helper()
		go nat.NewPacket([][]byte{[]byte("client")}, source, target, nil)
		select {
		case flow := <-handler:
			return flow
		case <-time.After(time.Second):
			t.Fatal("flow creation waited for the old writer")
			return udpRetirementFlow{}
		}
	}
	wait := func(ch <-chan struct{}, message string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal(message)
		}
	}
	old := open()
	batchWriter, ok := old.conn.(N.PacketBatchWriteCreator).CreatePacketBatchWriter()
	if !ok {
		t.Fatal("NAT did not expose a batch writer")
	}
	write := func(flow udpRetirementFlow, payload string) <-chan error {
		result := make(chan error, 1)
		go func() {
			result <- flow.conn.WritePacket(buf.As([]byte(payload)), target)
		}()
		return result
	}
	first := write(old, "admitted before expiry")
	wait(writer.admitted, "old writer did not enter device I/O")
	if !old.conn.(interface{ SetTimeout(time.Duration) bool }).SetTimeout(20 * time.Millisecond) {
		t.Fatal("could not schedule the old flow's expiry")
	}
	wait(old.ctx.Done(), "expiry waited for the stalled device write")
	next := open()
	if old.conn == next.conn || next.ctx.Err() != nil {
		t.Fatal("replacement did not get its own live flow")
	}
	late := write(old, "late single")
	fresh := write(next, "replacement")
	close(release)
	await := func(result <-chan error, want error) {
		t.Helper()
		select {
		case err := <-result:
			if !errors.Is(err, want) {
				t.Fatalf("write returned %v, want %v", err, want)
			}
		case <-time.After(time.Second):
			t.Fatal("writer did not finish")
		}
	}
	await(first, nil)
	await(fresh, nil)
	await(late, io.ErrClosedPipe)
	if err := batchWriter.WritePacketBatch([]*buf.Buffer{buf.As([]byte("late batch"))}, []M.Socksaddr{target}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("old batch writer returned %v", err)
	}
	for _, expected := range []string{"admitted before expiry", "replacement"} {
		select {
		case payload := <-writer.written:
			if payload != expected {
				t.Fatalf("device received %q, want %q", payload, expected)
			}
		default:
			t.Fatalf("device did not receive %q", expected)
		}
	}
	if len(writer.written) != 0 || old.conn.(interface{ SetTimeout(time.Duration) bool }).SetTimeout(time.Minute) {
		t.Fatal("old flow wrote to the device or refreshed its replacement")
	}
}
