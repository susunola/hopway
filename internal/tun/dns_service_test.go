//go:build !hopway_native && (darwin || linux)

package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/backend"
)

func TestVirtualDNSTCPReturnsFullReply(t *testing.T) {
	server := startDNSTransports(t, dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		reply := new(dns.Msg).SetReply(query)
		reply.Answer = []dns.RR{txtRecord(query.Question[0].Name, 6)}
		_ = w.WriteMsg(reply)
	}))
	backend.SetSocketControl(func(string, string, syscall.RawConn) error { return nil }, server)
	defer backend.SetSocketControl(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	options := Options{}
	options.defaults()
	service := &Service{
		options: options, fake: NewFakeIP(options.FakeRange), dnsCtx: ctx, dnsTCP: make(chan struct{}, 1),
	}
	client, ingress := net.Pipe()
	defer client.Close()
	defer ingress.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	finished := make(chan error, 1)
	go service.NewConnectionEx(ctx, ingress, M.ParseSocksaddr("127.0.0.1:12345"),
		M.Socksaddr{Addr: options.DNSAddress(), Port: 53}, func(err error) { finished <- err })
	query := dnsTestQuery(t, 0)
	for range 2 {
		if err := writeDNSFrame(client, query); err != nil {
			t.Fatal(err)
		}
		data, err := readDNSFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		var reply dns.Msg
		if err := reply.Unpack(data); err != nil || reply.Id != 123 || reply.Truncated || len(data) < 1200 {
			t.Fatalf("TCP DNS reply id=%d size=%d TC=%t err=%v", reply.Id, len(data), reply.Truncated, err)
		}
	}
	client.Close()
	select {
	case err := <-finished:
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("DNS session stayed open after client closed")
	}
}
