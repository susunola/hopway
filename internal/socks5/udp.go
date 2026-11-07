package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/peer"
	"mac-proxy/internal/wire"
)

// associate serves UDP ASSOCIATE: a UDP relay socket lives as long as the
// TCP control connection. Datagrams are accepted only from the client's IP,
// fragments are dropped, and each flow is routed by the engine like TCP.
func associate(client *net.TCPConn, dialPacket DialPacketFunc) error {
	local := client.LocalAddr().(*net.TCPAddr)
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		writeReply(client, replyFailure, nil)
		return err
	}
	defer relay.Close()
	bound := relay.LocalAddr().(*net.UDPAddr)
	if err := writeReply(client, replySuccess, &net.TCPAddr{IP: bound.IP, Port: bound.Port}); err != nil {
		return err
	}
	client.SetDeadline(time.Time{})
	allowed := client.RemoteAddr().(*net.TCPAddr).IP
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		io.Copy(io.Discard, client) // the association ends with the TCP connection
		cancel()
		relay.Close()
	}()

	var (
		mu      sync.Mutex
		session net.PacketConn
		source  *net.UDPAddr
	)
	defer func() {
		mu.Lock()
		if session != nil {
			session.Close()
		}
		mu.Unlock()
	}()
	buffer := make([]byte, 65535)
	for {
		n, from, err := relay.ReadFromUDP(buffer)
		if err != nil {
			return nil
		}
		if !from.IP.Equal(allowed) {
			continue
		}
		target, payload, err := parseDatagram(buffer[:n])
		if err != nil {
			continue
		}
		mu.Lock()
		if session == nil {
			source = from
			flowCtx := peer.WithAddrs(ctx, peer.Addrs{Client: from.AddrPort(), Server: bound.AddrPort(), Local: from.IP.IsLoopback()})
			session, err = dialPacket(flowCtx, "SOCKS5 UDP", target)
			if err != nil {
				session = nil
				mu.Unlock()
				continue
			}
			go replies(session, relay, func() *net.UDPAddr { mu.Lock(); defer mu.Unlock(); return source })
		}
		source = from
		current := session
		mu.Unlock()
		current.WriteTo(payload, M.ParseSocksaddr(target))
	}
}

func replies(session net.PacketConn, relay *net.UDPConn, client func() *net.UDPAddr) {
	buffer := make([]byte, 65535)
	for {
		session.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, from, err := session.ReadFrom(buffer)
		if err != nil {
			return
		}
		address, err := wire.EncodeAddress(M.SocksaddrFromNet(from).String())
		if socks, ok := from.(M.Socksaddr); ok {
			address, err = wire.EncodeAddress(socks.String())
		}
		if err != nil {
			continue
		}
		datagram := append([]byte{0, 0, 0}, address...)
		datagram = append(datagram, buffer[:n]...)
		if _, err := relay.WriteToUDP(datagram, client()); err != nil {
			return
		}
	}
}

// parseDatagram reads the SOCKS5 UDP header: RSV(2) FRAG(1) ATYP ADDR PORT.
func parseDatagram(data []byte) (string, []byte, error) {
	if len(data) < 4 || data[0] != 0 || data[1] != 0 {
		return "", nil, errors.New("bad header")
	}
	if data[2] != 0 {
		return "", nil, errors.New("fragmented datagrams are not supported")
	}
	reader := bytes.NewReader(data[4:])
	target, err := wire.ReadAddress(reader, data[3])
	if err != nil {
		return "", nil, err
	}
	return target, data[len(data)-reader.Len():], nil
}
