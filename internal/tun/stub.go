//go:build hopway_native || !(darwin || linux)

package tun

import (
	"context"
	"errors"
	"net/netip"
)

var errUnsupported = errors.New("TUN mode needs the sing-box build on macOS or Linux")

type Service struct{}

func Start(Options, Dial, DialPacket) (*Service, error) { return nil, errUnsupported }
func (*Service) Close() error                           { return nil }
func (*Service) ResetNetwork()                          {}
func (*Service) FakeIPStats() FakeIPStats               { return FakeIPStats{} }
func RunHelper(string, Options) error                   { return errUnsupported }
func OpenWithHelper(context.Context, string, Options) (int, string, error) {
	return 0, "", errUnsupported
}
func SystemDNS(netip.Addr) []string { return nil }

const (
	ServiceSocket = ""
	ServicePlist  = ""
)

func RunService(string, uint32, func(Options) (int, string, error)) error { return errUnsupported }
func CreateDevice(Options) (int, string, error)                           { return 0, "", errUnsupported }
func OpenWithService(context.Context, string, Options) (int, string, error) {
	return 0, "", errUnsupported
}
func ServiceAvailable(string) bool                                { return false }
func InstallService(string, uint32) error                         { return errUnsupported }
func UninstallService() error                                     { return errUnsupported }
func RunAsAdmin(context.Context, string, string, ...string) error { return errUnsupported }
