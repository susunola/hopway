package backend

import (
	"context"
	"net"

	"mac-proxy/internal/outbound"
)

// Native uses HopWay's own protocol code: socks5, http(s), trojan,
// shadowsocks AEAD, and basic VLESS/VMess over TCP or TLS.
type Native struct{}

func (Native) Name() string { return "native" }

func (Native) Check(node outbound.Node) error { return node.PrepareNative() }

type nativeInstance map[string]Dialer

func (Native) Open(nodes []outbound.Node, guard Guard) (Instance, error) {
	instance := nativeInstance{}
	for _, node := range nodes {
		if err := node.PrepareNative(); err != nil {
			return nil, nodeError(node.Name, err)
		}
		node := node
		dial := func(ctx context.Context, address string) (net.Conn, error) {
			return NetDial(ctx, "tcp", address, guard)
		}
		instance[node.Name] = DialerFunc(func(ctx context.Context, target string) (net.Conn, error) {
			return node.Dial(ctx, target, dial)
		})
	}
	return instance, nil
}

func (instance nativeInstance) Dialer(name string) (Dialer, bool) {
	dialer, ok := instance[name]
	return dialer, ok
}

func (nativeInstance) Close() error { return nil }

func (nativeInstance) ResetConnections() {}

type namedError struct {
	name string
	err  error
}

func (e namedError) Error() string { return "node " + `"` + e.name + `": ` + e.err.Error() }
func (e namedError) Unwrap() error { return e.err }

func nodeError(name string, err error) error { return namedError{name, err} }
