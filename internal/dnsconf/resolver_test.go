package dnsconf

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func startServer(t *testing.T, answer string) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(writer dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		if request.Question[0].Qtype == dns.TypeA && answer != "" {
			record, err := dns.NewRR(request.Question[0].Name + " 60 IN A " + answer)
			if err == nil {
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
	t.Cleanup(func() { server.Shutdown() })
	return packet.LocalAddr().String()
}

func TestResolverUsesTheServerSelectedByTheDomainRule(t *testing.T) {
	address := startServer(t, "10.1.2.3")
	resolver, err := New(&Config{
		Servers: []Server{{Name: "test", Address: address}},
		Rules:   []Rule{{Domain: "example.test", Server: "test"}},
		Default: SystemServer,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.ServerFor("a.example.test"); got != "test" {
		t.Fatalf("rule selected %q", got)
	}
	if got := resolver.ServerFor("example.test"); got != "test" {
		t.Fatalf("the rule must match the apex too, got %q", got)
	}
	if got := resolver.ServerFor("other.test"); got != SystemServer {
		t.Fatalf("unmatched domain selected %q", got)
	}
	addrs, server, err := resolver.Lookup(context.Background(), "a.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if server != "test" || len(addrs) != 1 || addrs[0].String() != "10.1.2.3" {
		t.Fatalf("lookup returned %v via %q", addrs, server)
	}
}

func TestResolverConfigValidation(t *testing.T) {
	for name, config := range map[string]Config{
		"duplicate server": {Servers: []Server{{Name: "a", Address: "1.1.1.1:53"}, {Name: "a", Address: "8.8.8.8:53"}}},
		"hostname address": {Servers: []Server{{Name: "a", Address: "dns.example:53"}}},
		"unknown rule":     {Rules: []Rule{{Domain: "x.test", Server: "missing"}}},
		"unknown default":  {Default: "missing"},
	} {
		if err := config.Validate(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestResolverWithoutConfigUsesTheSystem(t *testing.T) {
	resolver, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.ServerFor("example.test"); got != SystemServer {
		t.Fatalf("system default expected, got %q", got)
	}
	if _, _, err := resolver.Lookup(context.Background(), "127.0.0.1"); err != nil {
		t.Fatalf("literal address must not be queried: %v", err)
	}
}

func TestResolverReportsAnEmptyAnswer(t *testing.T) {
	address := startServer(t, "")
	resolver, err := New(&Config{Servers: []Server{{Name: "empty", Address: address}}, Default: "empty"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, server, err := resolver.Lookup(context.Background(), "missing.test")
	if err == nil || !strings.Contains(err.Error(), "empty answer") {
		t.Fatalf("empty answer not reported: %v", err)
	}
	if server != "empty" {
		t.Fatalf("server label %q", server)
	}
}
