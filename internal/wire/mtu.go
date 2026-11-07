package wire

import "fmt"

func ValidateTUNMTU(mtu uint32, ipv6 bool) error {
	minimum := uint32(68)
	if ipv6 {
		minimum = 1280
	}
	if mtu != 0 && (mtu < minimum || mtu > 65535) {
		return fmt.Errorf("TUN MTU must be 0 or between %d and 65535", minimum)
	}
	return nil
}
