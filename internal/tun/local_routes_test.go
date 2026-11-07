//go:build !hopway_native && (darwin || linux)

package tun

import (
	"net/netip"
	"syscall"
	"testing"

	stun "github.com/sagernet/sing-tun"
)

func TestLocalDiscoveryDoesNotOpenTUNOutbound(t *testing.T) {
	options := stun.Options{AutoRoute: true, Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		Inet6Address: []netip.Prefix{defaultAddress6}}
	excludeLocalRoutes(&options)
	routes, err := options.BuildAutoRouteRanges(false)
	if err != nil {
		t.Fatal(err)
	}
	covered := func(address netip.Addr) bool {
		for _, prefix := range routes {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	service := &Service{}
	for _, raw := range []string{"224.0.0.251:5353", "239.255.255.250:1900", "255.255.255.255:67", "[ff02::fb]:5353", "[fe80::1]:53"} {
		target := netip.MustParseAddrPort(raw)
		if covered(target.Addr()) {
			t.Errorf("%s included in TUN routes", target)
		}
		if verdict := service.JudgeFlow(syscall.IPPROTO_UDP, netip.AddrPort{}, target, nil); verdict.Action != stun.ActionDrop {
			t.Errorf("captured local packet %s could create an outbound: %v", target, verdict.Action)
		}
	}
	for _, raw := range []string{"198.18.0.2", "fc00::2", "172.19.0.2", "1.1.1.1", "2001:4860::1"} {
		if !covered(netip.MustParseAddr(raw)) {
			t.Errorf("proxy destination %s lost its route", raw)
		}
	}
}
