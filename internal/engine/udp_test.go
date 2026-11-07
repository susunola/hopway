//go:build !hopway_native

package engine

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/socks5"
	"mac-proxy/internal/wire"
)

func udpEchoServer(t *testing.T) *net.UDPAddr {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			conn.WriteTo(buffer[:n], from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func TestUDPThroughNodes(t *testing.T) {
	_, nodes := startServer(t)
	echo := udpEchoServer(t)
	config := Default()
	for _, node := range nodes {
		config.Nodes = append(config.Nodes, node)
	}
	config.Mode, config.Selected = "global", "DIRECT"
	core, err := New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	// Protocols that must carry UDP; AnyTLS has no UDP in sing-box.
	required := map[string]bool{"ss2022": true, "trojan": true, "vless-ws": true, "vmess-grpc": true,
		"reality": true, "hy2": true, "tuic": true, "DIRECT": true}
	names := []string{"DIRECT"}
	for name := range nodes {
		names = append(names, name)
	}
	target := echo.String()
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			core.SetPolicy(Policy{Mode: "global", Selected: name})
			conn, err := core.DialPacket(context.Background(), "test", target)
			if err != nil {
				if required[name] {
					t.Fatal(err)
				}
				t.Skipf("no UDP: %v", err)
			}
			defer conn.Close()
			destination := M.ParseSocksaddr(target)
			for i, size := range []int{12, 1200} { // a small datagram and a QUIC-sized one
				payload := make([]byte, size)
				copy(payload, "datagram "+strconv.Itoa(i))
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.WriteTo(payload, destination); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 2048)
				n, from, err := conn.ReadFrom(buffer)
				if err != nil || n != size || string(buffer[:9]) != "datagram " {
					t.Fatalf("echo %d bytes from %v: %v", n, from, err)
				}
				if M.SocksaddrFromNet(from).Port != echo.AddrPort().Port() {
					t.Fatalf("reply attributed to %v", from)
				}
			}
			conn.Close()
			records := core.Status().Connections
			last := records[len(records)-1]
			if last.Network != "udp" || last.Via != name || last.Sent < 1212 || last.Recv < 1212 {
				t.Fatalf("record %+v", last)
			}
		})
	}
}

func TestSOCKS5UDPAssociate(t *testing.T) {
	_, nodes := startServer(t)
	echo := udpEchoServer(t)
	config := Default()
	config.Nodes = []outbound.Node{nodes["ss2022"]}
	config.Mode, config.Selected = "global", "ss2022"
	core, err := New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	listener, _ := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer listener.Close()
	go func() {
		for {
			client, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			go func() { defer client.Close(); socks5.HandleWithUDP(client, core.Dial, core.DialPacket) }()
		}
	}()
	control, _ := net.Dial("tcp", listener.Addr().String())
	defer control.Close()
	control.SetDeadline(time.Now().Add(5 * time.Second))
	control.Write([]byte{5, 1, 0})
	io.ReadFull(control, make([]byte, 2))
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}) // UDP ASSOCIATE from 0.0.0.0:0
	reply := make([]byte, 10)
	if _, err := io.ReadFull(control, reply); err != nil || reply[1] != 0 {
		t.Fatalf("associate reply %v %v", reply, err)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}
	udp, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer udp.Close()
	header, _ := wire.EncodeAddress(echo.String())
	datagram := append(append([]byte{0, 0, 0}, header...), []byte("over socks udp")...)
	udp.SetDeadline(time.Now().Add(5 * time.Second))
	udp.WriteToUDP(datagram, relay)
	buffer := make([]byte, 2048)
	n, _, err := udp.ReadFromUDP(buffer)
	if err != nil || !bytes.HasSuffix(buffer[:n], []byte("over socks udp")) || !bytes.Equal(buffer[3:3+len(header)], header) {
		t.Fatalf("udp reply %q %v", buffer[:n], err)
	}
	if record := core.Status().Connections; len(record) == 0 || record[0].Network != "udp" || record[0].Via != "ss2022" || record[0].Inbound != "SOCKS5 UDP" {
		t.Fatalf("record %+v", record)
	}
	// Closing the control connection ends the association.
	control.Close()
	time.Sleep(100 * time.Millisecond)
	udp.WriteToUDP(datagram, relay)
	udp.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := udp.ReadFromUDP(buffer); err == nil {
		t.Fatal("association outlived its control connection")
	}
}
