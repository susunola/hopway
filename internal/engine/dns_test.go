package engine

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/miekg/dns"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/dnsconf"
)

// A direct connection to a domain configured with a custom DNS server must
// use that server, and the connection record must say which one answered.
func TestDirectDialUsesConfiguredDNSAndRecordsIt(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(writer dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		if request.Question[0].Qtype == dns.TypeA {
			if record, err := dns.NewRR(request.Question[0].Name + " 60 IN A 127.0.0.1"); err == nil {
				reply.Answer = append(reply.Answer, record)
			}
		}
		writer.WriteMsg(reply)
	})
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packet, Handler: mux}
	go server.ActivateAndServe()
	defer server.Shutdown()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	target := "probe.dnstest:" + strconv.Itoa(mustPort(t, port))

	config := Default()
	config.DNS = &dnsconf.Config{
		Servers: []dnsconf.Server{{Name: "lab", Address: packet.LocalAddr().String()}},
		Default: "lab",
	}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	conn, err := core.Dial(context.Background(), "test", target)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	status := core.Status()
	if len(status.Connections) == 0 {
		t.Fatal("no connection record")
	}
	record := status.Connections[0]
	if record.DNSServer != "lab" {
		t.Fatalf("record says dns server %q, want lab", record.DNSServer)
	}
	if record.Server != target {
		t.Fatalf("record server %q, want the dialed target %q", record.Server, target)
	}
}

func mustPort(t *testing.T, value string) int {
	t.Helper()
	port, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
