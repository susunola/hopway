//go:build linux && !hopway_native

package tun

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/peer"
)

// TestDevice runs real traffic through a TUN device. It needs root and
// /dev/net/tun, so it is skipped elsewhere.
func TestDevice(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("no /dev/net/tun")
	}
	tcpEcho, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tcpEcho.Close()
	go func() {
		for {
			c, err := tcpEcho.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udpEcho, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer udpEcho.Close()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := udpEcho.ReadFrom(buffer)
			if err != nil {
				return
			}
			udpEcho.WriteTo(buffer[:n], from)
		}
	}()
	loopback := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	backend.Resolver.Pin("echo.test", loopback)
	backend.Resolver.Pin("udp.test", loopback)
	defer backend.Resolver.Pin("echo.test", nil)
	defer backend.Resolver.Pin("udp.test", nil)

	stalledTLS, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stalledTLS.Close()
	config := engine.Default()
	config.Nodes = []outbound.Node{{Name: "stall", Type: "trojan", Server: stalledTLS.Addr().String(), Password: "fixture"}}
	config.Rules = []engine.Rule{
		{Type: engine.RuleDomain, Value: "blocked.test", Via: "REJECT"},
		{Type: engine.RuleDomain, Value: "stalled.test", Via: "stall"},
		{Type: engine.RuleIPCIDR, Value: "203.0.113.0/24", NoResolve: true, Via: "REJECT"},
		{Type: engine.RuleMatch, Via: "DIRECT"},
	}
	core, err := engine.New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	// An upstream DNS server for queries HopWay does not answer itself.
	upstream := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg).SetReply(r)
		q := r.Question[0]
		header := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
		switch q.Qtype {
		case dns.TypeA:
			reply.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("192.168.5.2")}}
		case dns.TypeAAAA:
			reply.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("fd00::2")}}
		case dns.TypeTXT:
			reply.Answer = []dns.RR{&dns.TXT{Hdr: header, Txt: []string{"from upstream"}}}
		}
		w.WriteMsg(reply)
	})}
	started := make(chan struct{})
	upstream.NotifyStartedFunc = func() { close(started) }
	go upstream.ListenAndServe()
	<-started
	defer upstream.Shutdown()

	resolvers := []string{upstream.PacketConn.LocalAddr().String()}
	service, err := Start(Options{Name: "hwtest0", MTU: 40000, AutoRoute: true, UpstreamDNS: resolvers,
		LocalDNS: resolvers, FakeIPExceptions: []string{"Home.Example."}, DisableSniffing: true,
		RouteAddress: []netip.Prefix{DefaultFakeRange, netip.MustParsePrefix("203.0.113.0/24")}}, core.Dial, core.DialPacket)
	if err != nil {
		t.Skipf("cannot create a TUN device here: %v", err)
	}
	defer service.Close()
	time.Sleep(200 * time.Millisecond)
	if fd, err := deviceFD(service.device); err != nil || fd <= 0 {
		t.Fatalf("device descriptor: %d %v", fd, err)
	}

	lookup := func(t *testing.T, name string) netip.Addr {
		t.Helper()
		query := new(dns.Msg)
		query.SetQuestion(dns.Fqdn(name), dns.TypeA)
		client := &dns.Client{Timeout: 3 * time.Second}
		reply, _, err := client.Exchange(query, "172.19.0.2:53") // hijacked by the device
		if err != nil || len(reply.Answer) != 1 {
			t.Fatalf("dns %s: %v %v", name, reply, err)
		}
		addr, _ := netip.AddrFromSlice(reply.Answer[0].(*dns.A).A.To4())
		if !DefaultFakeRange.Contains(addr) {
			t.Fatalf("%s resolved to %s, not a fake address", name, addr)
		}
		return addr
	}

	// TCP to a fake address reaches the target by name.
	echoPort := tcpEcho.Addr().(*net.TCPAddr).Port
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(lookup(t, "echo.test").String(), strconv.Itoa(echoPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("through the tunnel"))
	reply := make([]byte, 18)
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "through the tunnel" {
		t.Fatalf("tcp echo %q %v", reply, err)
	}
	conn.Close()
	records := core.Status().Connections
	if len(records) == 0 || records[0].Inbound != "TUN" || records[0].TargetSource != peer.TargetFakeIP ||
		records[0].Target != net.JoinHostPort("echo.test", strconv.Itoa(echoPort)) {
		t.Fatalf("engine did not see the name: %+v", records)
	}

	// A REJECT rule applies to TUN traffic by name too.
	blocked, err := net.DialTimeout("tcp", net.JoinHostPort(lookup(t, "blocked.test").String(), "80"), 3*time.Second)
	if err == nil {
		blocked.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = blocked.Read(make([]byte, 1))
		blocked.Close()
	}
	if err == nil {
		t.Fatal("blocked name was not rejected")
	}

	// UDP to a fake address is relayed directly, replies come back from it.
	fakeUDP := lookup(t, "udp.test")
	udpConn, err := net.Dial("udp", net.JoinHostPort(fakeUDP.String(), strconv.Itoa(udpEcho.LocalAddr().(*net.UDPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(3 * time.Second))
	udpConn.Write([]byte("datagram"))
	buffer := make([]byte, 64)
	n, err := udpConn.Read(buffer)
	if err != nil || string(buffer[:n]) != "datagram" {
		t.Fatalf("udp echo %q %v", buffer[:n], err)
	}
	// A larger MTU must not truncate payloads to the former 16 KiB copy buffer.
	large := bytes.Repeat([]byte{0x6b}, 32000)
	received := make([]byte, len(large)+1)
	for _, payload := range [][]byte{large, nil, []byte("short packet after jumbo")} {
		udpConn.SetDeadline(time.Now().Add(3 * time.Second))
		if n, err := udpConn.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("sent %d / %d UDP bytes: %v", n, len(payload), err)
		}
		n, err := udpConn.Read(received)
		if err != nil || !bytes.Equal(received[:n], payload) {
			t.Fatalf("received %d / %d UDP bytes: %v", n, len(payload), err)
		}
	}
	// Non-address queries sent to the tunnel go to the real upstream.
	txt := new(dns.Msg)
	txt.SetQuestion("info.test.", dns.TypeTXT)
	answer, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(txt, "172.19.0.2:53")
	if err != nil || len(answer.Answer) != 1 || answer.Answer[0].(*dns.TXT).Txt[0] != "from upstream" {
		t.Fatalf("forwarded query: %v %v", answer, err)
	}

	t.Run("Fake IP exceptions", func(t *testing.T) {
		dnsClient := &dns.Client{Timeout: 2 * time.Second}
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			query := new(dns.Msg).SetQuestion("nas.home.example.", qtype)
			answer, _, err := dnsClient.Exchange(query, "172.19.0.2:53")
			if err != nil || len(answer.Answer) != 1 {
				t.Fatalf("exception query: %v %v", answer, err)
			}
			switch rr := answer.Answer[0].(type) {
			case *dns.A:
				if qtype != dns.TypeA || rr.A.String() != "192.168.5.2" {
					t.Fatalf("exception A: %s", rr.A)
				}
			case *dns.AAAA:
				if qtype != dns.TypeAAAA || rr.AAAA.String() != "fd00::2" {
					t.Fatalf("exception AAAA: %s", rr.AAAA)
				}
			default:
				t.Fatalf("unexpected exception answer %T", rr)
			}
		}
		lookup(t, "nothome.example")
	})

	t.Run("sniffing disabled", func(t *testing.T) {
		const target = "203.0.113.9:80"
		client, err := net.DialTimeout("tcp4", target, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		client.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
		_, _ = client.Read(make([]byte, 1))
		for _, record := range core.Status().Connections {
			if record.Target == target && record.TargetSource == peer.TargetIP && record.State == "blocked" {
				return
			}
		}
		t.Fatal("literal TCP target was not routed as an IP")
	})

	t.Run("cancel stalled TLS with full read ahead", func(t *testing.T) {
		target := net.JoinHostPort(lookup(t, "stalled.test").String(), "443")
		client, err := net.DialTimeout("tcp4", target, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		tcp := client.(*net.TCPConn)
		client.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Write(make([]byte, 32<<10)); err != nil {
			t.Fatal(err)
		}
		stalledTLS.SetDeadline(time.Now().Add(3 * time.Second))
		origin, err := stalledTLS.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer origin.Close()
		origin.SetReadDeadline(time.Now().Add(2 * time.Second))
		var hello [4096]byte
		if n, err := origin.Read(hello[:]); err != nil || n == 0 || hello[0] != 0x16 {
			t.Fatalf("expected a real TLS handshake, got %d bytes and %v", n, err)
		}
		// Give the bounded ingress reader time to fill before the reset.
		time.Sleep(250 * time.Millisecond)
		if err := tcp.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		tcp.Close()
		origin.SetReadDeadline(started.Add(2 * time.Second))
		for {
			_, err := origin.Read(hello[:])
			if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
				break
			}
			if err != nil {
				t.Fatalf("TUN reset did not release the TLS socket: %v", err)
			}
		}
		t.Logf("real TUN client reset closed stalled TLS in %s", time.Since(started))
	})
}
