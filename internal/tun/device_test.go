//go:build linux && !hopway_native

package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
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
		buffer := make([]byte, 2048)
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

	config := engine.Default()
	config.Rules = []engine.Rule{
		{Type: engine.RuleDomain, Value: "blocked.test", Via: "REJECT"},
		{Type: engine.RuleMatch, Via: "DIRECT"},
	}
	core, err := engine.New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	// An upstream DNS server for queries HopWay does not answer itself.
	upstream := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"from upstream"}}}
		w.WriteMsg(reply)
	})}
	started := make(chan struct{})
	upstream.NotifyStartedFunc = func() { close(started) }
	go upstream.ListenAndServe()
	<-started
	defer upstream.Shutdown()

	service, err := Start(Options{Name: "hwtest0", AutoRoute: true, UpstreamDNS: []string{upstream.PacketConn.LocalAddr().String()},
		RouteAddress: []netip.Prefix{DefaultFakeRange}}, core.Dial, core.DialPacket)
	if err != nil {
		t.Skipf("cannot create a TUN device here: %v", err)
	}
	defer service.Close()
	time.Sleep(200 * time.Millisecond)
	if fd, err := deviceFD(service.device); err != nil || fd <= 0 {
		t.Fatalf("device descriptor: %d %v", fd, err)
	}

	lookup := func(name string) netip.Addr {
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
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(lookup("echo.test").String(), strconv.Itoa(echoPort)), 3*time.Second)
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
	if len(records) == 0 || records[0].Inbound != "TUN" || records[0].Target != net.JoinHostPort("echo.test", strconv.Itoa(echoPort)) {
		t.Fatalf("engine did not see the name: %+v", records)
	}

	// A REJECT rule applies to TUN traffic by name too.
	blocked, err := net.DialTimeout("tcp", net.JoinHostPort(lookup("blocked.test").String(), "80"), 3*time.Second)
	if err == nil {
		blocked.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = blocked.Read(make([]byte, 1))
		blocked.Close()
	}
	if err == nil {
		t.Fatal("blocked name was not rejected")
	}

	// UDP to a fake address is relayed directly, replies come back from it.
	fakeUDP := lookup("udp.test")
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
	// Non-address queries sent to the tunnel go to the real upstream.
	txt := new(dns.Msg)
	txt.SetQuestion("info.test.", dns.TypeTXT)
	answer, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(txt, "172.19.0.2:53")
	if err != nil || len(answer.Answer) != 1 || answer.Answer[0].(*dns.TXT).Txt[0] != "from upstream" {
		t.Fatalf("forwarded query: %v %v", answer, err)
	}
	_ = context.Background
}
