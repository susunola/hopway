package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/peer"
	"mac-proxy/internal/wire"
)

const (
	maxUDPAssociationTargets = 32
	udpSendQueue             = 8
	udpSessionIdle           = 5 * time.Minute
	udpWriteTimeout          = 2 * time.Second
)

// associate serves UDP ASSOCIATE: a UDP relay socket lives as long as the
// TCP control connection. Datagrams are accepted only from the client's IP,
// fragments are dropped, and each flow is routed by the engine like TCP.
func associate(client *net.TCPConn, requested string, dialPacket DialPacketFunc) error {
	requestedPort := M.ParseSocksaddr(requested).Port // Zero means the client has no bound port yet.
	local := client.LocalAddr().(*net.TCPAddr)
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		writeReply(client, replyFailure, nil)
		return err
	}
	bound := relay.LocalAddr().(*net.UDPAddr)
	if err := writeReply(client, replySuccess, &net.TCPAddr{IP: bound.IP, Port: bound.Port}); err != nil {
		relay.Close()
		return err
	}
	client.SetDeadline(time.Time{})
	allowed := client.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	defer func() {
		cancel()
		relay.Close()
		workers.Wait()
	}()
	go func() {
		io.Copy(io.Discard, client) // the association ends with the TCP connection
		cancel()
		relay.Close()
	}()

	var mu sync.Mutex
	sessions := make(map[string]*udpSession)
	workerSlots := make(chan struct{}, maxUDPAssociationTargets+1)
	var source netip.AddrPort
	started := time.Now()
	buffer := make([]byte, 65535)
	for {
		n, from, err := relay.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return nil
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from.Addr() != allowed || (requestedPort != 0 && from.Port() != requestedPort) ||
			(source.IsValid() && from != source) {
			continue
		}
		target, payload, err := parseDatagram(buffer[:n])
		if err != nil {
			continue
		}
		source = from
		mu.Lock()
		session := sessions[target]
		if session == nil || session.ctx.Err() != nil {
			// Allow one retiring session while opening its replacement.
			// A target flood cannot accumulate canceled workers.
			select {
			case workerSlots <- struct{}{}:
			default:
				mu.Unlock()
				continue
			}
			if len(sessions) >= maxUDPAssociationTargets {
				var oldestTarget string
				var oldest *udpSession
				for name, candidate := range sessions {
					if oldest == nil || candidate.lastActive.Load() < oldest.lastActive.Load() {
						oldestTarget, oldest = name, candidate
					}
				}
				oldest.cancel()
				delete(sessions, oldestTarget)
			}
			flowCtx := peer.WithAddrs(ctx, peer.Addrs{Client: from, Server: bound.AddrPort(), Local: allowed.IsLoopback()})
			sessionCtx, stop := context.WithCancel(flowCtx)
			session = &udpSession{ctx: sessionCtx, cancel: stop, started: started, queue: make(chan []byte, udpSendQueue)}
			session.touch()
			sessions[target] = session
			workers.Add(1)
			go func(session *udpSession, target string, from netip.AddrPort) {
				defer workers.Done()
				defer func() { <-workerSlots }()
				session.run(relay, from, target, dialPacket)
				mu.Lock()
				if sessions[target] == session {
					delete(sessions, target)
				}
				mu.Unlock()
			}(session, target, from)
		}
		mu.Unlock()
		// The relay loop is the only producer. A slow outbound can fill
		// its own queue but does not block other targets on the association.
		if len(session.queue) < cap(session.queue) {
			session.queue <- bytes.Clone(payload)
		}
	}
}

type udpSession struct {
	ctx        context.Context
	cancel     context.CancelFunc
	started    time.Time
	lastActive atomic.Int64
	queue      chan []byte
}

func (s *udpSession) touch() {
	s.lastActive.Store(time.Since(s.started).Nanoseconds())
}

func (s *udpSession) run(relay *net.UDPConn, client netip.AddrPort, target string, dial DialPacketFunc) {
	defer s.cancel()
	upstream, err := dial(s.ctx, "SOCKS5 UDP", target)
	if err != nil {
		return
	}
	closeUpstream := sync.OnceFunc(func() { _ = upstream.Close() })
	stop := context.AfterFunc(s.ctx, closeUpstream)
	defer stop()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		s.replies(upstream, relay, client)
		s.cancel()
	}()
	defer func() {
		closeUpstream()
		<-readDone
	}()
	destination := M.ParseSocksaddr(target)
	for {
		select {
		case <-s.ctx.Done():
			return
		case data := <-s.queue:
			if s.ctx.Err() != nil {
				return
			}
			_ = upstream.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
			if _, err := upstream.WriteTo(data, destination); err != nil {
				return
			}
			s.touch()
		}
	}
}

func (s *udpSession) replies(session net.PacketConn, relay *net.UDPConn, client netip.AddrPort) {
	buffer := make([]byte, 65535)
	for s.ctx.Err() == nil {
		remaining := udpSessionIdle - (time.Since(s.started) - time.Duration(s.lastActive.Load()))
		if remaining <= 0 {
			return
		}
		_ = session.SetReadDeadline(time.Now().Add(remaining))
		n, from, err := session.ReadFrom(buffer)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return
		}
		if s.ctx.Err() != nil {
			return
		}
		s.touch()
		address, err := wire.EncodeAddress(M.SocksaddrFromNet(from).String())
		if socks, ok := from.(M.Socksaddr); ok {
			address, err = wire.EncodeAddress(socks.String())
		}
		if err != nil {
			continue
		}
		datagram := append([]byte{0, 0, 0}, address...)
		datagram = append(datagram, buffer[:n]...)
		if _, err := relay.WriteToUDPAddrPort(datagram, client); err != nil {
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
