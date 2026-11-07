//go:build !hopway_native && (darwin || linux)

// Package tun captures all traffic of the machine through a TUN device
// (utun on macOS) and hands it to the engine: TCP is proxied by the normal
// rules, DNS is answered with fake IPs so rules see domain names, and other
// UDP is relayed directly when the rules say DIRECT.
package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	stun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/peer"
	"mac-proxy/internal/wire"
)

type Service struct {
	options Options
	device  stun.Tun
	stack   stun.Stack
	network stun.NetworkUpdateMonitor
	monitor stun.DefaultInterfaceMonitor
	fake    *FakeIP
	dial    Dial
	decide  Decide
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
}

func Start(options Options, dial Dial, decide Decide) (*Service, error) {
	options.defaults()
	s := &Service{options: options, fake: NewFakeIP(options.FakeRange), dial: dial, decide: decide}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	finder := control.NewDefaultInterfaceFinder()
	var err error
	if s.network, err = stun.NewNetworkUpdateMonitor(logger.NOP()); err != nil {
		return nil, err
	}
	if s.monitor, err = stun.NewDefaultInterfaceMonitor(s.network, logger.NOP(), stun.DefaultInterfaceMonitorOptions{InterfaceFinder: finder}); err != nil {
		return nil, err
	}
	if err := s.network.Start(); err != nil {
		return nil, err
	}
	if err := s.monitor.Start(); err != nil {
		s.network.Close()
		return nil, err
	}
	// Everything HopWay sends itself leaves through the physical interface.
	backend.SetSocketControl(func(network, address string, conn syscall.RawConn) error {
		iface := s.monitor.DefaultInterface()
		if iface == nil {
			return nil
		}
		return control.BindToInterface(finder, iface.Name, iface.Index)(network, address, conn)
	}, options.UpstreamDNS...)
	tunOptions := stun.Options{
		Name: options.Name, Inet4Address: []netip.Prefix{options.Address}, MTU: options.MTU,
		AutoRoute: options.AutoRoute, Inet4RouteAddress: options.RouteAddress, FileDescriptor: options.FD,
		InterfaceMonitor: s.monitor, InterfaceFinder: finder,
	}
	if tunOptions.Name == "" && options.FD == 0 {
		tunOptions.Name = stun.CalculateInterfaceName("")
	}
	fail := func(err error) (*Service, error) {
		s.Close()
		return nil, err
	}
	if s.device, err = stun.New(tunOptions); err != nil {
		return fail(err)
	}
	s.stack, err = stun.NewStack("system", stun.StackOptions{
		Context: s.ctx, Tun: s.device, TunOptions: tunOptions, UDPTimeout: 5 * time.Minute,
		Handler: s, Logger: logger.NOP(), InterfaceFinder: finder,
	})
	if err != nil {
		return fail(err)
	}
	if err := s.device.Start(); err != nil {
		return fail(err)
	}
	if err := s.stack.Start(); err != nil {
		return fail(err)
	}
	return s, nil
}

func (s *Service) Close() error {
	var err error
	s.once.Do(func() {
		s.cancel()
		backend.SetSocketControl(nil)
		var errs []error
		if s.stack != nil {
			errs = append(errs, s.stack.Close())
		}
		if s.device != nil {
			errs = append(errs, s.device.Close())
		}
		if s.monitor != nil {
			errs = append(errs, s.monitor.Close())
		}
		if s.network != nil {
			errs = append(errs, s.network.Close())
		}
		err = errors.Join(errs...)
	})
	return err
}

// ResetNetwork drops stack state tied to the previous network.
func (s *Service) ResetNetwork() {
	if s.stack != nil {
		s.stack.ResetNetwork()
	}
}

// JudgeFlow sends every DNS query to NewDNSPacket and everything else to
// the connection handlers.
func (s *Service) JudgeFlow(network uint8, source, destination netip.AddrPort, _ []byte) stun.FlowVerdict {
	if network == syscall.IPPROTO_UDP && destination.Port() == 53 {
		return stun.FlowVerdict{Action: stun.ActionHijackDNS}
	}
	return stun.FlowVerdict{Action: stun.ActionAccept}
}

func (s *Service) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	query := append([]byte(nil), payload...)
	go func() {
		server := destination.String()
		// Queries addressed to the tunnel itself (the system DNS points
		// here in TUN mode) are forwarded to the real upstream.
		if destination.IsIP() && (s.options.Address.Contains(destination.Addr) || s.fake.Contains(destination.Addr)) {
			server = ""
			if upstreams := backend.UpstreamDNS(); len(upstreams) != 0 {
				server = upstreams[0]
			}
		}
		forward := func(ctx context.Context, payload []byte) ([]byte, error) {
			if server == "" {
				return nil, errors.New("no upstream DNS server")
			}
			return forwarder(server, backend.BoundDial)(ctx, payload)
		}
		reply, err := answerDNS(s.ctx, query, s.fake, forward)
		if err != nil || reply == nil {
			return
		}
		writer.WritePacket(buf.As(reply), destination)
	}()
}

// target turns a destination into what the engine routes on: the name
// behind a fake IP, or the address itself.
func (s *Service) target(destination M.Socksaddr) string {
	if destination.IsIP() && s.fake.Contains(destination.Addr) {
		if name, ok := s.fake.Lookup(destination.Addr); ok {
			return net.JoinHostPort(name, strconv.Itoa(int(destination.Port)))
		}
	}
	return destination.String()
}

// done calls onClose, which the stack may leave nil.
func done(onClose N.CloseHandlerFunc, err error) {
	if onClose != nil {
		onClose(err)
	}
}

func (s *Service) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	target := s.target(destination)
	if destination.IsIP() && s.fake.Contains(destination.Addr) && target == destination.String() {
		// A fake address we no longer know: the mapping wrapped around.
		conn.Close()
		done(onClose, errors.New("unknown fake address"))
		return
	}
	reader := conn
	if destination.IsIP() && !s.fake.Contains(destination.Addr) {
		// An application that connects to an IP directly may still say
		// which site it wants in its TLS ClientHello or HTTP Host header.
		if name, replay := sniff(conn); name != "" {
			target = net.JoinHostPort(name, strconv.Itoa(int(destination.Port)))
			reader = replay
		} else {
			reader = replay
		}
	}
	ctx = peer.WithAddrs(ctx, peer.Addrs{Client: source.AddrPort(), Server: destination.AddrPort(), Local: true})
	upstream, err := s.dial(ctx, "TUN", target)
	if err != nil {
		conn.Close()
		done(onClose, err)
		return
	}
	wire.Relay(reader, upstream)
	done(onClose, nil)
}

// NewPacketConnectionEx relays UDP directly when the rules route it to
// DIRECT and drops it otherwise. Dropping makes QUIC applications (browsers
// on UDP 443) fall back to TCP, which then goes through the proxy.
func (s *Service) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if s.decide(s.target(destination)) != "DIRECT" {
		conn.Close()
		done(onClose, nil)
		return
	}
	resolve := func(addr M.Socksaddr) (*net.UDPAddr, error) {
		target := addr
		if addr.IsIP() && s.fake.Contains(addr.Addr) {
			name, ok := s.fake.Lookup(addr.Addr)
			if !ok {
				return nil, errors.New("unknown fake address")
			}
			target = M.ParseSocksaddrHostPort(name, addr.Port)
		}
		if target.IsFqdn() {
			addrs, err := backend.Resolver.Lookup(ctx, target.Fqdn)
			if err != nil || len(addrs) == 0 {
				return nil, errors.New("cannot resolve " + target.Fqdn)
			}
			return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrs[0], target.Port)), nil
		}
		return net.UDPAddrFromAddrPort(target.AddrPort()), nil
	}
	var once sync.Once
	var remote net.PacketConn
	finish := func(err error) {
		once.Do(func() {
			conn.Close()
			if remote != nil {
				remote.Close()
			}
			done(onClose, err)
		})
	}
	replyTo := map[string]M.Socksaddr{} // real address -> what the app sent to (a fake IP)
	var mu sync.Mutex
	receive := func() {
		buffer := make([]byte, 65535)
		for {
			remote.SetReadDeadline(time.Now().Add(5 * time.Minute))
			n, from, err := remote.ReadFrom(buffer)
			if err != nil {
				finish(nil)
				return
			}
			mu.Lock()
			original, ok := replyTo[from.String()]
			mu.Unlock()
			if !ok {
				original = M.SocksaddrFromNet(from)
			}
			if err := conn.WritePacket(buf.As(append([]byte(nil), buffer[:n]...)), original); err != nil {
				finish(err)
				return
			}
		}
	}
	for {
		packet := buf.NewPacket()
		to, err := conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			finish(nil)
			return
		}
		addr, err := resolve(to)
		if err == nil && remote == nil {
			// The socket is opened on the first datagram, once the peer is known.
			if remote, err = backend.ListenPacket(ctx, addr.AddrPort().Addr()); err != nil {
				packet.Release()
				finish(err)
				return
			}
			go receive()
		}
		if err == nil {
			mu.Lock()
			replyTo[addr.String()] = to
			mu.Unlock()
			_, err = remote.WriteTo(packet.Bytes(), addr)
		}
		packet.Release()
		if err != nil && !errors.Is(err, io.ErrShortWrite) {
			continue // one bad datagram does not end the flow
		}
	}
}
