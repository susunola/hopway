package tun

import (
	"context"
	"net"
	"net/netip"
	"time"
)

const DefaultMTU = 9000
const dnsTimeout = 5 * time.Second

type DNSSettings struct {
	TimeoutMS       int  `json:"timeoutMs"`
	ExceptionCount  int  `json:"exceptionCount"`
	SniffingEnabled bool `json:"sniffingEnabled"`
}

type Options struct {
	FD               int // a device opened by the privileged helper; 0 creates one (needs root)
	Name             string
	MTU              uint32
	Address          netip.Prefix // the device's own address
	AutoRoute        bool
	RouteAddress     []netip.Prefix // limits auto-route to these ranges (default: everything)
	FakeRange        netip.Prefix
	UpstreamDNS      []string // host:port servers for HopWay's own lookups and forwarded queries
	LocalDNS         []string // system resolvers, before adding public fallback servers
	IPv6             bool     // give the device an IPv6 address, route ::/0 and answer AAAA with fake IPv6
	UDPIdleTimeout   time.Duration
	FakeIPExceptions []string
	DNSTimeoutMS     int
	DisableSniffing  bool
}

var defaultAddress6 = netip.MustParsePrefix("fdfe:dcba:9876::1/126")

func (o *Options) defaults() {
	if o.MTU == 0 {
		o.MTU = DefaultMTU
	}
	if !o.Address.IsValid() {
		o.Address = netip.MustParsePrefix("172.19.0.1/30")
	}
	if !o.FakeRange.IsValid() {
		o.FakeRange = DefaultFakeRange
	}
}

func (o Options) dnsForwardTimeout() time.Duration {
	if o.DNSTimeoutMS == 0 {
		return dnsTimeout
	}
	return time.Duration(o.DNSTimeoutMS) * time.Millisecond
}

// Dial and Decide connect the device to the engine.
type Dial func(ctx context.Context, inbound, target string) (net.Conn, error)

// DialPacket opens a UDP session routed by the engine; WriteTo takes
// M.Socksaddr destinations and ReadFrom returns the address written to.
type DialPacket func(ctx context.Context, inbound, target string) (net.PacketConn, error)

// DNSAddress is the address the system DNS points at in TUN mode: the
// device's peer address, so queries are routed into the tunnel.
func (o Options) DNSAddress() netip.Addr {
	o.defaults()
	return o.Address.Addr().Next()
}
