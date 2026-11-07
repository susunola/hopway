package tun

import (
	"net"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func routedNetworks(interfaces map[int]string) ([]networkPrefix, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	var prefixes []networkPrefix
	for _, message := range messages {
		m, ok := message.(*route.RouteMessage)
		if !ok || interfaces[m.Index] == "" {
			continue
		}
		if prefix := activeRoutePrefix(m); prefix.IsValid() {
			prefixes = append(prefixes, networkPrefix{prefix, "路由 " + interfaces[m.Index]})
		}
	}
	return prefixes, nil
}

func activeRoutePrefix(m *route.RouteMessage) netip.Prefix {
	if m.Flags&unix.RTF_UP == 0 || m.Flags&(unix.RTF_LLINFO|unix.RTF_WASCLONED) != 0 ||
		len(m.Addrs) <= unix.RTAX_DST {
		return netip.Prefix{}
	}
	dst := routeIP(m.Addrs[unix.RTAX_DST])
	if !dst.IsValid() {
		return netip.Prefix{}
	}
	if m.Flags&unix.RTF_HOST != 0 {
		return netip.PrefixFrom(dst, dst.BitLen())
	}
	if len(m.Addrs) <= unix.RTAX_NETMASK {
		return netip.Prefix{}
	}
	mask := routeIP(m.Addrs[unix.RTAX_NETMASK])
	if !mask.IsValid() {
		return netip.Prefix{}
	}
	size, bits := net.IPMask(mask.AsSlice()).Size()
	if size <= 1 || bits != dst.BitLen() {
		// Default and split-default routes do not describe a LAN subnet.
		return netip.Prefix{}
	}
	return netip.PrefixFrom(dst, size).Masked()
}

func routeIP(address route.Addr) netip.Addr {
	switch ip := address.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(ip.IP)
	case *route.Inet6Addr:
		return netip.AddrFrom16(ip.IP)
	default:
		return netip.Addr{}
	}
}
