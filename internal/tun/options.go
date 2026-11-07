package tun

import (
	"context"
	"net"
	"net/netip"
)

type Options struct {
	FD           int // a device opened by the privileged helper; 0 creates one (needs root)
	Name         string
	MTU          uint32
	Address      netip.Prefix // the device's own address
	AutoRoute    bool
	RouteAddress []netip.Prefix // limits auto-route to these ranges (default: everything)
	FakeRange    netip.Prefix
	UpstreamDNS  []string // host:port servers for HopWay's own lookups and forwarded queries
}

func (o *Options) defaults() {
	if o.MTU == 0 {
		o.MTU = 9000
	}
	if !o.Address.IsValid() {
		o.Address = netip.MustParsePrefix("172.19.0.1/30")
	}
	if !o.FakeRange.IsValid() {
		o.FakeRange = DefaultFakeRange
	}
}

// Dial and Decide connect the device to the engine.
type Dial func(ctx context.Context, inbound, target string) (net.Conn, error)
type Decide func(target string) string

// DNSAddress is the address the system DNS points at in TUN mode: the
// device's peer address, so queries are routed into the tunnel.
func (o Options) DNSAddress() netip.Addr {
	o.defaults()
	return o.Address.Addr().Next()
}
