//go:build !hopway_native && (darwin || linux)

package tun

import (
	"net/netip"

	stun "github.com/sagernet/sing-tun"
)

var (
	ipv4Multicast = netip.MustParsePrefix("224.0.0.0/4")
	ipv4Broadcast = netip.MustParsePrefix("255.255.255.255/32")
	ipv6Multicast = netip.MustParsePrefix("ff00::/8")
	ipv6LinkLocal = netip.MustParsePrefix("fe80::/10")
)

func excludeLocalRoutes(options *stun.Options) {
	options.Inet4RouteExcludeAddress = []netip.Prefix{ipv4Multicast, ipv4Broadcast}
	options.Inet6RouteExcludeAddress = []netip.Prefix{ipv6Multicast, ipv6LinkLocal}
}

func belongsToLocalLink(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsMulticast() || ipv4Broadcast.Contains(addr) || ipv6LinkLocal.Contains(addr)
}
