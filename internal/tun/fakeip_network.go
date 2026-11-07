package tun

import (
	"fmt"
	"net"
	"net/netip"
)

type networkPrefix struct {
	prefix netip.Prefix
	source string
}

// CheckFakeIPNetworks checks the existing network before any TUN routes or
// DNS settings are changed.
func (o Options) CheckFakeIPNetworks() error {
	return o.checkFakeIPNetworks("")
}

func (o Options) checkFakeIPNetworks(ignoreInterface string) error {
	o.defaults()
	if err := o.fakeIPConflict(nil); err != nil {
		return err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("读取本机网卡以检查 Fake IP 网段: %w", err)
	}
	names := make(map[int]string, len(interfaces))
	var prefixes []networkPrefix
	for _, iface := range interfaces {
		if iface.Name == ignoreInterface || iface.Flags&net.FlagUp == 0 {
			continue
		}
		names[iface.Index] = iface.Name
		addresses, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("读取网卡 %s 以检查 Fake IP 网段: %w", iface.Name, err)
		}
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil {
				prefixes = append(prefixes, networkPrefix{prefix.Masked(), "网卡 " + iface.Name})
			}
		}
	}
	if err := o.fakeIPConflict(prefixes); err != nil {
		return err
	}
	routes, err := routedNetworks(names)
	if err != nil {
		return fmt.Errorf("读取本机路由以检查 Fake IP 网段: %w", err)
	}
	return o.fakeIPConflict(routes)
}

func (o Options) fakeIPConflict(networks []networkPrefix) error {
	if !o.FakeRange.Addr().Is4() || o.FakeRange.Bits() < 2 || o.FakeRange.Bits() > 30 {
		return fmt.Errorf("无效的 IPv4 Fake IP 网段 %s", o.FakeRange)
	}
	pools := []netip.Prefix{o.FakeRange.Masked()}
	if o.IPv6 {
		pools = append(pools, DefaultFakeRange6)
	}
	if pools[0].Overlaps(o.Address) {
		return fmt.Errorf("Fake IP 网段 %s 与 TUN 设备网段 %s 重叠", pools[0], o.Address.Masked())
	}
	for _, network := range networks {
		for _, pool := range pools {
			if pool.Overlaps(network.prefix) {
				return fmt.Errorf("Fake IP 网段 %s 与%s 的网段 %s 重叠", pool, network.source, network.prefix)
			}
		}
	}
	return nil
}
