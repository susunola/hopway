//go:build !hopway_native && (darwin || linux)

// Package tun captures all traffic of the machine through a TUN device
// (utun on macOS) and hands it to the engine: TCP is proxied by the normal
// rules, DNS is answered with fake IPs so rules see domain names, and other
// UDP is relayed directly when the rules say DIRECT.
package tun

import (
	"bufio"
	"context"
	"errors"
	"fmt"
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
	options        Options
	controlsSocket bool
	device         stun.Tun
	stack          stun.Stack
	network        stun.NetworkUpdateMonitor
	monitor        stun.DefaultInterfaceMonitor
	fake           *FakeIP
	dial           Dial
	dialPacket     DialPacket
	ctx            context.Context
	cancel         context.CancelFunc
	once           sync.Once
	dnsMu          sync.Mutex
	dnsCtx         context.Context
	cancelDNS      context.CancelFunc
	dnsUDP         chan struct{}
	dnsTCP         chan struct{}
}

const tunUDPIdle = 5 * time.Minute

func Start(options Options, dial Dial, dialPacket DialPacket) (*Service, error) {
	options.defaults()
	fd := options.FD
	defer func() {
		if fd > 0 {
			closeFD(fd)
		}
	}()
	if err := wire.ValidateTUNMTU(options.MTU, options.IPv6); err != nil {
		return nil, err
	}
	if fd > 0 {
		if err := verifyDevice(fd, options.Name); err != nil {
			return nil, fmt.Errorf("invalid device from TUN helper: %w", err)
		}
	}
	s := &Service{options: options, fake: NewFakeIP(options.FakeRange), dial: dial, dialPacket: dialPacket}
	if options.IPv6 {
		s.fake.EnableIPv6(DefaultFakeRange6)
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.dnsCtx, s.cancelDNS = context.WithCancel(s.ctx)
	s.dnsUDP, s.dnsTCP = make(chan struct{}, 64), make(chan struct{}, 32)
	finder := control.NewDefaultInterfaceFinder()
	var err error
	fail := func(err error) (*Service, error) {
		return nil, errors.Join(err, s.Close())
	}
	if s.network, err = stun.NewNetworkUpdateMonitor(logger.NOP()); err != nil {
		return fail(err)
	}
	if s.monitor, err = stun.NewDefaultInterfaceMonitor(s.network, logger.NOP(), stun.DefaultInterfaceMonitorOptions{InterfaceFinder: finder}); err != nil {
		return fail(err)
	}
	if err := s.network.Start(); err != nil {
		return fail(err)
	}
	if err := s.monitor.Start(); err != nil {
		return fail(err)
	}
	// Everything HopWay sends itself leaves through the physical interface.
	backend.SetSocketControl(func(network, address string, conn syscall.RawConn) error {
		iface := s.monitor.DefaultInterface()
		if iface == nil {
			return nil
		}
		return control.BindToInterface(finder, iface.Name, iface.Index)(network, address, conn)
	}, options.UpstreamDNS...)
	s.controlsSocket = true
	tunOptions := stun.Options{
		Name: options.Name, Inet4Address: []netip.Prefix{options.Address}, MTU: options.MTU,
		AutoRoute: options.AutoRoute, Inet4RouteAddress: options.RouteAddress, FileDescriptor: options.FD,
		InterfaceMonitor: s.monitor, InterfaceFinder: finder,
	}
	if options.IPv6 {
		tunOptions.Inet6Address = []netip.Prefix{defaultAddress6}
	}
	if tunOptions.Name == "" && options.FD == 0 {
		tunOptions.Name = stun.CalculateInterfaceName("")
	}
	if s.device, err = stun.New(tunOptions); err != nil {
		return fail(err)
	}
	fd = 0 // the TUN device now owns the descriptor
	s.stack, err = stun.NewStack("system", stun.StackOptions{
		Context: s.ctx, Tun: s.device, TunOptions: tunOptions, UDPTimeout: tunUDPIdle,
		// The first packet selects the outbound. Separate destinations
		// must not share that choice even if the app uses one UDP socket.
		UDPMapping: stun.NATMappingAddressAndPortDependent, UDPNATMax: 1024,
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
		if s.controlsSocket {
			backend.SetSocketControl(nil)
		}
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
	s.dnsMu.Lock()
	s.cancelDNS()
	s.dnsCtx, s.cancelDNS = context.WithCancel(s.ctx)
	s.dnsMu.Unlock()
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

func (s *Service) dnsView() context.Context {
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	return s.dnsCtx
}

func (s *Service) isVirtualDNS(destination M.Socksaddr) bool {
	return destination.IsIP() && (s.options.Address.Contains(destination.Addr) ||
		defaultAddress6.Contains(destination.Addr) || s.fake.Contains(destination.Addr))
}

func (s *Service) replyDNS(ctx context.Context, payload []byte, destination M.Socksaddr) ([]byte, error) {
	server := destination.String()
	// Queries for the virtual DNS server use a physical upstream.
	if s.isVirtualDNS(destination) {
		server = ""
		if upstreams := backend.UpstreamDNS(); len(upstreams) != 0 {
			server = upstreams[0]
		}
	}
	reply, err := answerDNS(ctx, payload, s.fake, func(ctx context.Context, query []byte) ([]byte, error) {
		if server == "" {
			return nil, errors.New("no upstream DNS server")
		}
		return forwardDNS(ctx, query, server, backend.BoundDial)
	})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return dnsFailure(payload)
	}
	return reply, nil
}

func (s *Service) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	if len(payload) < dnsHeaderSize || len(payload) > maxDNSUDP {
		return
	}
	ctx := s.dnsView()
	select {
	case s.dnsUDP <- struct{}{}:
	case <-ctx.Done():
		return
	default:
		return
	}
	query := append([]byte(nil), payload...)
	go func() {
		defer func() { <-s.dnsUDP }()
		reply, err := s.replyDNS(ctx, query, destination)
		if err == nil {
			// Reserve space for the IPv6 and UDP headers as well.
			reply, err = limitDNSUDP(query, reply, min(maxDNSUDP, int(s.options.MTU)-48))
		}
		if err == nil && ctx.Err() == nil {
			writer.WritePacket(buf.As(reply), destination)
		}
	}()
}

func (s *Service) serveDNSTCP(ctx context.Context, conn net.Conn, destination M.Socksaddr) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopView := context.AfterFunc(s.dnsView(), cancel)
	defer stopView()
	stopConn := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopConn()
	select {
	case s.dnsTCP <- struct{}{}:
		defer func() { <-s.dnsTCP }()
	default:
		return errors.New("too many concurrent DNS connections")
	}
	for {
		if err := conn.SetReadDeadline(time.Now().Add(dnsTimeout)); err != nil {
			return err
		}
		query, err := readDNSFrame(conn)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		reply, err := s.replyDNS(ctx, query, destination)
		if err != nil {
			return err
		}
		if err := conn.SetWriteDeadline(time.Now().Add(dnsTimeout)); err != nil {
			return err
		}
		if err := writeDNSFrame(conn, reply); err != nil {
			return err
		}
	}
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
	if destination.Port == 53 && s.isVirtualDNS(destination) {
		err := s.serveDNSTCP(ctx, conn, destination)
		conn.Close()
		done(onClose, err)
		return
	}
	target := s.target(destination)
	if destination.IsIP() && s.fake.Contains(destination.Addr) && target == destination.String() {
		// A fake address we no longer know: the mapping wrapped around.
		conn.Close()
		done(onClose, errors.New("unknown fake address"))
		return
	}
	var reader *bufio.Reader
	if destination.IsIP() && !s.fake.Contains(destination.Addr) {
		// An application that connects to an IP directly may still say
		// which site it wants in its TLS ClientHello or HTTP Host header.
		name, replay := sniff(conn)
		reader = replay.Reader
		if name != "" {
			target = net.JoinHostPort(name, strconv.Itoa(int(destination.Port)))
		}
	}
	if reader == nil {
		reader = bufio.NewReader(conn)
	}
	ctx = peer.WithAddrs(ctx, peer.Addrs{Client: source.AddrPort(), Server: destination.AddrPort(), Local: true})
	upstream, err := wire.DialWithClient(ctx, conn, reader, func(ctx context.Context) (net.Conn, error) {
		return s.dial(ctx, "TUN", target)
	})
	if err != nil {
		conn.Close()
		done(onClose, err)
		return
	}
	if reader.Buffered() > 0 {
		conn = &wire.BufferedConn{Conn: conn, Reader: reader}
	}
	wire.Relay(conn, upstream)
	done(onClose, nil)
}

// NewPacketConnectionEx relays a UDP flow through whatever the rules pick:
// DIRECT, or a node that carries UDP. If the route cannot carry UDP the
// flow is dropped, and QUIC applications fall back to TCP.
func (s *Service) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	target := s.target(destination)
	if destination.IsIP() && s.fake.Contains(destination.Addr) && target == destination.String() {
		wire.TUNUDPDrops.Add(wire.UDPInvalid, 1)
		conn.Close()
		done(onClose, errors.New("unknown fake address"))
		return
	}
	ctx = peer.WithAddrs(ctx, peer.Addrs{Client: source.AddrPort(), Server: destination.AddrPort(), Local: true})
	remote, err := s.dialPacket(ctx, "TUN", target)
	if err != nil {
		if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			wire.TUNUDPDrops.Add(backend.PacketDropReason(err), 1)
		}
		conn.Close()
		done(onClose, err)
		return
	}
	var once sync.Once
	finish := func(err error) {
		once.Do(func() {
			conn.Close()
			remote.Close()
			done(onClose, err)
		})
	}
	written := M.ParseSocksaddr(target)
	lifetime, _ := conn.(interface{ SetTimeout(time.Duration) bool })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := remote.ReadFrom(buffer)
			if err != nil {
				finish(nil)
				return
			}
			key := M.SocksaddrFromNet(from)
			if socks, ok := from.(M.Socksaddr); ok {
				key = socks
			}
			original := key
			if key == written {
				original = destination // restore the original address, often a fake IP
			} else if !original.IsIP() {
				continue
			}
			if err := conn.WritePacket(buf.As(append([]byte(nil), buffer[:n]...)), original); err != nil {
				finish(err)
				return
			}
			// The NAT table already refreshes uploads. Refresh downloads
			// here and let the table, rather than a second timer, own expiry.
			if lifetime != nil && !lifetime.SetTimeout(tunUDPIdle) {
				finish(nil)
				return
			}
		}
	}()
	for {
		packet := buf.NewPacket()
		to, err := conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			finish(nil)
			return
		}
		if to == destination {
			_, err := remote.WriteTo(packet.Bytes(), written)
			if err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				wire.TUNUDPDrops.Add(backend.PacketDropReason(err), 1)
			}
		} else {
			wire.TUNUDPDrops.Add(wire.UDPInvalid, 1)
		}
		packet.Release()
	}
}
