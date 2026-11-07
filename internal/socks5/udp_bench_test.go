package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/wire"
)

func BenchmarkUDPRelayLoopback(b *testing.B) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { echo.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := echo.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			echo.WriteToUDPAddrPort(buffer[:n], from)
		}
	}()
	client, relay := openUDPAssociation(b, func(ctx context.Context, _, target string) (net.PacketConn, error) {
		return backend.DirectPacket(ctx, target, nil)
	})
	address, err := wire.EncodeAddress(echo.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	const payloadSize = 1200
	request := append([]byte{0, 0, 0}, address...)
	payloadOffset := len(request)
	request = append(request, bytes.Repeat([]byte{0xa5}, payloadSize)...)
	reply := make([]byte, len(request)+1)
	if err := client.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		b.Fatal(err)
	}
	roundTrip := func(sequence uint64) {
		binary.BigEndian.PutUint64(request[payloadOffset:], sequence)
		if _, err := client.WriteToUDP(request, relay); err != nil {
			b.Fatal(err)
		}
		n, from, err := client.ReadFromUDPAddrPort(reply)
		if err != nil || from.Addr().Unmap() != relay.AddrPort().Addr().Unmap() ||
			from.Port() != relay.AddrPort().Port() || !bytes.Equal(reply[:n], request) {
			b.Fatalf("packet %d: %d bytes from %v, %v", sequence, n, from, err)
		}
	}
	for i := range 32 {
		roundTrip(uint64(i))
	}
	b.ReportAllocs()
	b.SetBytes(2 * payloadSize)
	var sequence uint64 = 32
	for b.Loop() {
		roundTrip(sequence)
		sequence++
	}
}
