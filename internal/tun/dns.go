package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
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
	if query.Response {
		return nil, errDNSResponse
	}
	if query.Opcode != dns.OpcodeQuery || len(query.Question) != 1 {
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

const (
	dnsHeaderSize = 12
	maxDNSUDP     = 4096
	dnsTimeout    = 5 * time.Second
)

var errDNSResponse = errors.New("DNS response does not match query")

type dnsDial func(context.Context, string, string) (net.Conn, error)

// forwardDNS uses a connected UDP socket and retries over TCP if the
// matching UDP response is truncated or exceeds our receive budget.
func forwardDNS(ctx context.Context, payload []byte, server string, dial dnsDial) ([]byte, error) {
	if len(payload) > dns.MaxMsgSize {
		return nil, dns.ErrBuf
	}
	var query dns.Msg
	if err := query.Unpack(payload); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	upstream := append([]byte(nil), payload...)
	id := dns.Id()
	binary.BigEndian.PutUint16(upstream, id)
	var reply []byte
	var err error
	if len(upstream) <= maxDNSUDP {
		reply, err = exchangeDNSUDP(ctx, server, dial, upstream, id, &query)
		if err != nil {
			return nil, err
		}
	}
	if reply == nil {
		reply, err = exchangeDNSTCP(ctx, server, dial, upstream, id, &query)
		if err != nil {
			return nil, err
		}
	}
	binary.BigEndian.PutUint16(reply, query.Id)
	return reply, nil
}

func exchangeDNSUDP(ctx context.Context, server string, dial dnsDial, payload []byte, id uint16, query *dns.Msg) ([]byte, error) {
	conn, cleanup, err := openDNSSocket(ctx, "udp", server, dial)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	var buffer [maxDNSUDP + 1]byte
	for {
		n, err := conn.Read(buffer[:])
		if err != nil {
			return nil, err
		}
		packet := buffer[:n]
		if !matchesDNSResponse(packet, id, query) {
			continue
		}
		if n > maxDNSUDP || packet[2]&0x02 != 0 {
			return nil, nil // retry the same query at the same upstream
		}
		var reply dns.Msg
		if err := reply.Unpack(packet); err != nil {
			continue
		}
		return append([]byte(nil), packet...), nil
	}
}

func exchangeDNSTCP(ctx context.Context, server string, dial dnsDial, payload []byte, id uint16, query *dns.Msg) ([]byte, error) {
	conn, cleanup, err := openDNSSocket(ctx, "tcp", server, dial)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if err := writeDNSFrame(conn, payload); err != nil {
		return nil, err
	}
	packet, err := readDNSFrame(conn)
	if err != nil {
		return nil, err
	}
	if !matchesDNSResponse(packet, id, query) || packet[2]&0x02 != 0 {
		return nil, errDNSResponse
	}
	var reply dns.Msg
	if err := reply.Unpack(packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func openDNSSocket(ctx context.Context, network, server string, dial dnsDial) (net.Conn, func(), error) {
	conn, err := dial(ctx, network, server)
	if err != nil {
		return nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	return conn, func() {
		stop()
		conn.Close()
	}, nil
}

// Inspect the question before the answer records, which may be cut off.
func matchesDNSResponse(packet []byte, id uint16, query *dns.Msg) bool {
	if len(packet) < dnsHeaderSize || binary.BigEndian.Uint16(packet) != id ||
		packet[2]&0x80 == 0 || int(packet[2]>>3)&0xf != query.Opcode ||
		int(binary.BigEndian.Uint16(packet[4:])) != len(query.Question) {
		return false
	}
	offset := dnsHeaderSize
	for _, q := range query.Question {
		name, next, err := dns.UnpackDomainName(packet, offset)
		if err != nil || len(packet)-next < 4 || !strings.EqualFold(name, q.Name) ||
			binary.BigEndian.Uint16(packet[next:]) != q.Qtype ||
			binary.BigEndian.Uint16(packet[next+2:]) != q.Qclass {
			return false
		}
		offset = next + 4
	}
	return true
}

func readDNSFrame(reader io.Reader) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(prefix[:])
	if size < dnsHeaderSize {
		return nil, dns.ErrBuf
	}
	packet := make([]byte, size)
	_, err := io.ReadFull(reader, packet)
	return packet, err
}

func writeDNSFrame(writer io.Writer, payload []byte) error {
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(len(payload)))
	copy(frame[2:], payload)
	n, err := writer.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}

func limitDNSUDP(query, response []byte, ceiling int) ([]byte, error) {
	limit := dns.MinMsgSize
	if len(response) <= limit {
		return response, nil
	}
	var request dns.Msg
	if err := request.Unpack(query); err != nil {
		return nil, err
	}
	if opt := request.IsEdns0(); opt != nil {
		limit = min(max(limit, ceiling), max(limit, int(opt.UDPSize())))
	}
	if len(response) <= limit {
		return response, nil
	}
	var reply dns.Msg
	if err := reply.Unpack(response); err != nil {
		return nil, err
	}
	reply.Truncate(limit)
	packet, err := reply.Pack()
	if err == nil && len(packet) > limit {
		// Even the question or EDNS options can exceed the client budget.
		short := new(dns.Msg).SetRcode(&request, reply.Rcode&0xf)
		short.Truncated = true
		packet, err = short.Pack()
	}
	return packet, err
}

func dnsFailure(payload []byte) ([]byte, error) {
	var query dns.Msg
	if err := query.Unpack(payload); err != nil {
		return nil, err
	}
	if query.Response {
		return nil, errDNSResponse
	}
	return new(dns.Msg).SetRcode(&query, dns.RcodeServerFailure).Pack()
}
