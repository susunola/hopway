package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/bits"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/peer"
	"mac-proxy/internal/wire"
)

const (
	maxUDPAssociationTargets = 32
	udpSendQueue             = 8
	udpSessionIdle           = 5 * time.Minute
	udpWriteTimeout          = 2 * time.Second
	maxUDPAssociations       = 256
	udpReplyHeadroom         = 3 + 1 + 1 + 255 + 2 // RSV/FRAG, ATYP, domain length, name and port
)

var udpAssociations = make(chan struct{}, maxUDPAssociations)
var errFragmentedDatagram = errors.New("fragmented datagrams are not supported")

// associate serves UDP ASSOCIATE: a UDP relay socket lives as long as the
// TCP control connection. Datagrams are accepted only from the client's IP,
// fragments are dropped, and each flow is routed by the engine like TCP.
func associate(client *net.TCPConn, requested string, dialPacket DialPacketFunc, idle time.Duration) error {
	select {
	case udpAssociations <- struct{}{}:
		defer func() { <-udpAssociations }()
	default:
		return errors.Join(backend.ErrPacketCongested, writeReply(client, replyFailure, nil))
	}
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
			wire.SOCKSUDPDrops.Add(wire.UDPInvalid, 1)
			continue
		}
		target, payload, err := parseDatagram(buffer[:n])
		if err != nil {
			reason := wire.UDPInvalid
			if errors.Is(err, errFragmentedDatagram) {
				reason = wire.UDPFragment
			}
			wire.SOCKSUDPDrops.Add(reason, 1)
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
				wire.SOCKSUDPDrops.Add(wire.UDPQueueFull, 1)
				mu.Unlock()
				continue
			}
			flowCtx := peer.WithAddrs(ctx, peer.Addrs{Client: from, Server: bound.AddrPort(), Local: allowed.IsLoopback()})
			sessionCtx, stop := context.WithCancel(flowCtx)
			session = &udpSession{ctx: sessionCtx, cancel: stop, started: started, idle: idle, queue: make(chan []byte, udpSendQueue)}
			if !session.enqueue(payload) {
				stop()
				<-workerSlots
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
			session.touch()
			sessions[target] = session
			workers.Add(1)
			go func(session *udpSession, target string, from netip.AddrPort) {
				defer workers.Done()
				defer func() { <-workerSlots }()
				err := session.run(relay, from, target, dialPacket)
				mu.Lock()
				if sessions[target] == session {
					delete(sessions, target)
				}
				session.discard(err)
				mu.Unlock()
			}(session, target, from)
		} else {
			session.enqueue(payload)
		}
		mu.Unlock()
	}
}

type udpSession struct {
	ctx        context.Context
	cancel     context.CancelFunc
	started    time.Time
	idle       time.Duration
	lastActive atomic.Int64
	queue      chan []byte
}

func (s *udpSession) touch() {
	s.lastActive.Store(time.Since(s.started).Nanoseconds())
}

func (s *udpSession) enqueue(payload []byte) bool {
	if len(s.queue) == cap(s.queue) || !wire.UDPQueue.TryReserve(udpQueueCharge(len(payload))) {
		wire.SOCKSUDPDrops.Add(wire.UDPQueueFull, 1)
		return false
	}
	buffer := buf.Get(len(payload))
	s.queue <- append(buffer[:0], payload...)
	return true
}

// discard runs with the association lock, after the only consumer exits.
func (s *udpSession) discard(err error) {
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		wire.SOCKSUDPDrops.Add(backend.PacketDropReason(err), len(s.queue))
	}
	for len(s.queue) > 0 {
		releaseUDPData(<-s.queue)
	}
}

func releaseUDPData(data []byte) {
	if data != nil {
		_ = buf.Put(data)
	}
	wire.UDPQueue.Release(udpQueueCharge(len(data)))
}

func udpQueueCharge(size int) int {
	// Include the slice header and round up to cover allocation size classes.
	return 32 + 1<<bits.Len(uint(max(size, 64)-1))
}

func (s *udpSession) run(relay *net.UDPConn, client netip.AddrPort, target string, dial DialPacketFunc) error {
	defer s.cancel()
	upstream, err := dial(s.ctx, "SOCKS5 UDP", target)
	if err != nil {
		return err
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
			return s.ctx.Err()
		case data := <-s.queue:
			if s.ctx.Err() != nil {
				releaseUDPData(data)
				return s.ctx.Err()
			}
			_ = upstream.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
			_, err := upstream.WriteTo(data, destination)
			releaseUDPData(data)
			if err != nil {
				if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return err
				}
				wire.SOCKSUDPDrops.Add(backend.PacketDropReason(err), 1)
				if errors.Is(err, backend.ErrPacketCongested) {
					continue
				}
				return err
			}
			s.touch()
		}
	}
}

func (s *udpSession) replies(session net.PacketConn, relay *net.UDPConn, client netip.AddrPort) {
	buffer := make([]byte, udpReplyHeadroom+65535)
	var header [udpReplyHeadroom]byte
	for s.ctx.Err() == nil {
		remaining := s.idle - (time.Since(s.started) - time.Duration(s.lastActive.Load()))
		if remaining <= 0 {
			return
		}
		_ = session.SetReadDeadline(time.Now().Add(remaining))
		n, from, err := session.ReadFrom(buffer[udpReplyHeadroom:])
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
		prefix, err := wire.AppendAddress(header[:3], M.SocksaddrFromNet(from).String())
		if err != nil {
			continue
		}
		start := udpReplyHeadroom - len(prefix)
		copy(buffer[start:udpReplyHeadroom], prefix)
		if _, err := relay.WriteToUDPAddrPort(buffer[start:udpReplyHeadroom+n], client); err != nil {
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
		return "", nil, errFragmentedDatagram
	}
	reader := bytes.NewReader(data[4:])
	target, err := wire.ReadAddress(reader, data[3])
	if err != nil {
		return "", nil, err
	}
	return target, data[len(data)-reader.Len():], nil
}
