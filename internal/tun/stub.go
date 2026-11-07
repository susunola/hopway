//go:build hopway_native || !(darwin || linux)

package tun

import (
	"errors"
	"net/netip"
)

var errUnsupported = errors.New("TUN mode needs the sing-box build on macOS or Linux")

type Service struct{}

func Start(Options, Dial, DialPacket) (*Service, error) { return nil, errUnsupported }
func (*Service) Close() error                           { return nil }
func (*Service) ResetNetwork()                          {}
func RunHelper(string, Options) error                   { return errUnsupported }
func OpenWithHelper(string, bool) (int, string, error)  { return 0, "", errUnsupported }
func SystemDNS(netip.Addr) []string                     { return nil }
