// Package peer carries the local client's socket addresses from an inbound
// listener to the engine, so the engine can find which process connected.
package peer

import (
	"context"
	"net"
	"net/netip"
)

type Addrs struct {
	Client netip.AddrPort // the application's socket
	Server netip.AddrPort // what it connected to (HopWay's listener, or the real target under TUN)
	Local  bool           // the client is a process on this machine
}

type key struct{}

func With(ctx context.Context, client, server net.Addr) context.Context {
	addrs := Addrs{Client: addrPort(client), Server: addrPort(server)}
	if !addrs.Client.IsValid() {
		return ctx
	}
	addrs.Local = addrs.Client.Addr().Unmap().IsLoopback()
	return context.WithValue(ctx, key{}, addrs)
}

// WithAddrs records addresses known to belong to a local process.
func WithAddrs(ctx context.Context, addrs Addrs) context.Context {
	return context.WithValue(ctx, key{}, addrs)
}

func From(ctx context.Context) (Addrs, bool) {
	addrs, ok := ctx.Value(key{}).(Addrs)
	return addrs, ok
}

func addrPort(addr net.Addr) netip.AddrPort {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.AddrPort()
	case nil:
		return netip.AddrPort{}
	}
	parsed, _ := netip.ParseAddrPort(addr.String())
	return parsed
}
