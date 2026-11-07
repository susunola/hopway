package tun

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// answerDNS builds the reply to a query hijacked from the TUN device.
// A records get fake IPs; AAAA gets a fake IPv6 address when IPv6 is on,
// otherwise an empty answer so applications use IPv4; anything else is forwarded upstream through a
// socket bound to the physical interface (never back into the TUN).
func answerDNS(ctx context.Context, payload []byte, fake *FakeIP, forward func(context.Context, []byte) ([]byte, error)) ([]byte, error) {
	var query dns.Msg
	if err := query.Unpack(payload); err != nil {
		return nil, err
	}
	if len(query.Question) != 1 {
		return forward(ctx, payload)
	}
	question := query.Question[0]
	switch question.Qtype {
	case dns.TypeA, dns.TypeAAAA:
	default:
		return forward(ctx, payload)
	}
	if question.Qclass != dns.ClassINET || dns.IsFqdn(question.Name) && isLocalName(question.Name) {
		return forward(ctx, payload)
	}
	reply := new(dns.Msg)
	reply.SetReply(&query)
	reply.RecursionAvailable = true
	switch question.Qtype {
	case dns.TypeA:
		addr := fake.Allocate(question.Name)
		reply.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
			A:   net.IP(addr.AsSlice()),
		}}
	case dns.TypeAAAA:
		if addr := fake.Allocate6(question.Name); addr.IsValid() {
			reply.Answer = []dns.RR{&dns.AAAA{
				Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1},
				AAAA: net.IP(addr.AsSlice()),
			}}
		}
	}
	return reply.Pack()
}

// isLocalName keeps mDNS and private names on the real resolver.
func isLocalName(name string) bool {
	for _, suffix := range []string{".local.", ".lan.", ".home.arpa.", ".in-addr.arpa.", ".ip6.arpa."} {
		if dns.IsSubDomain(suffix[1:], name) {
			return true
		}
	}
	return false
}

// forwarder sends a raw query to server over UDP using dial.
func forwarder(server string, dial func(ctx context.Context, network, address string) (net.Conn, error)) func(context.Context, []byte) ([]byte, error) {
	return func(ctx context.Context, payload []byte) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		conn, err := dial(ctx, "udp", server)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		deadline, _ := ctx.Deadline()
		conn.SetDeadline(deadline)
		if _, err := conn.Write(payload); err != nil {
			return nil, err
		}
		buffer := make([]byte, 65535)
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, err
		}
		return buffer[:n], nil
	}
}
