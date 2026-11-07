package tun

import (
	"net/netip"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestFakeIPPreflightDistinguishesRouteAndDefault(t *testing.T) {
	m := &route.RouteMessage{Flags: unix.RTF_UP, Addrs: make([]route.Addr, unix.RTAX_NETMASK+1)}
	m.Addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: [4]byte{198, 19, 8, 12}}
	m.Addrs[unix.RTAX_NETMASK] = &route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}}
	if got := activeRoutePrefix(m); got != netip.MustParsePrefix("198.19.8.0/24") {
		t.Fatalf("static route prefix: %v", got)
	}
	m.Flags |= unix.RTF_WASCLONED
	if got := activeRoutePrefix(m); got.IsValid() {
		t.Fatalf("cloned route treated as a network: %v", got)
	}
	m.Flags = unix.RTF_UP
	m.Addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: [4]byte{128, 0, 0, 0}}
	m.Addrs[unix.RTAX_NETMASK] = &route.Inet4Addr{IP: [4]byte{128, 0, 0, 0}}
	if got := activeRoutePrefix(m); got.IsValid() {
		t.Fatalf("split default treated as a LAN route: %v", got)
	}
}
