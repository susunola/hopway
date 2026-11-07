//go:build linux && !hopway_native

package tun

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
)

func BenchmarkDeviceUDPRelayLoopback(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("needs root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		b.Skip("no /dev/net/tun")
	}
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
	const host = "udp-throughput.test"
	backend.Resolver.Pin(host, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	b.Cleanup(func() { backend.Resolver.Pin(host, nil) })
	core, err := engine.New(engine.Default(), backend.Default())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { core.Close() })
	service, err := Start(Options{Name: "hwbench0", AutoRoute: true, RouteAddress: []netip.Prefix{DefaultFakeRange}},
		core.Dial, core.DialPacket)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { service.Close() })
	target := netip.AddrPortFrom(service.fake.Allocate(host), echo.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { client.Close() })
	const payloadSize = 1200
	request := bytes.Repeat([]byte{0xa5}, payloadSize)
	reply := make([]byte, len(request)+1)
	if err := client.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		b.Fatal(err)
	}
	roundTrip := func(sequence uint64) {
		binary.BigEndian.PutUint64(request, sequence)
		if _, err := client.Write(request); err != nil {
			b.Fatal(err)
		}
		n, err := client.Read(reply)
		if err != nil || !bytes.Equal(reply[:n], request) {
			b.Fatalf("packet %d: %d bytes, %v", sequence, n, err)
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
