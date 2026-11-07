//go:build hopway_native || !(darwin || linux)

package process

import "net/netip"

func Lookup(client, server netip.AddrPort) (*Owner, error) { return nil, ErrUnsupported }
