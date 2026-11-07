//go:build !hopway_native

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	sbout "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"mac-proxy/internal/outbound"
	"mac-proxy/internal/wire"
)

// Default is the backend used by regular builds.
func Default() Backend { return SingBox{} }

// SingBox runs nodes on the sing-box protocol stack. Every node detours
// through a HopWay-owned socket dialer, so DNS and connect timings are ours
// and loop protection applies to every protocol, QUIC included.
type SingBox struct{}

const traceTag = "hopway-trace"
const traceType = "hopway_trace"

func (SingBox) Name() string { return "sing-box" }

func (SingBox) Check(node outbound.Node) error {
	if err := node.Validate(); err != nil {
		return err
	}
	outboundJSON, err := Convert(node)
	if err != nil {
		return err
	}
	delete(outboundJSON, "detour")
	outboundJSON["detour"] = traceTag
	instance, err := build([]map[string]any{outboundJSON}, nil)
	if err != nil {
		return err
	}
	return instance.Close()
}

type singInstance struct {
	box     *box.Box
	dialers map[string]Dialer
}

func (SingBox) Open(nodes []outbound.Node, guard Guard) (Instance, error) {
	outbounds := make([]map[string]any, 0, len(nodes))
	for _, node := range nodes {
		if node.Name == traceTag {
			return nil, nodeError(node.Name, errors.New("name is reserved"))
		}
		if err := node.Validate(); err != nil {
			return nil, nodeError(node.Name, err)
		}
		converted, err := Convert(node)
		if err != nil {
			return nil, nodeError(node.Name, err)
		}
		outbounds = append(outbounds, converted)
	}
	instance, err := build(outbounds, guard)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, err
	}
	result := &singInstance{box: instance, dialers: make(map[string]Dialer)}
	for _, node := range nodes {
		chunked := node.Type == "anytls"
		out, ok := instance.Outbound().Outbound(node.Name)
		if !ok {
			instance.Close()
			return nil, nodeError(node.Name, errors.New("outbound was not created"))
		}
		result.dialers[node.Name] = DialerFunc(func(ctx context.Context, target string) (net.Conn, error) {
			destination := M.ParseSocksaddr(target)
			if !destination.IsValid() {
				return nil, errors.New("invalid destination")
			}
			conn, err := out.DialContext(ctx, N.NetworkTCP, destination)
			if err != nil {
				return nil, err
			}
			if N.NeedHandshakeForWrite(conn) {
				conn = newHandshakeConn(conn)
			}
			if chunked {
				conn = &chunkConn{conn}
			}
			return conn, nil
		})
	}
	return result, nil
}

func (instance *singInstance) Dialer(name string) (Dialer, bool) {
	dialer, ok := instance.dialers[name]
	return dialer, ok
}

func (instance *singInstance) Close() error { return instance.box.Close() }

func (instance *singInstance) ResetConnections() { instance.box.CloseIdleConnections() }

func build(outbounds []map[string]any, guard Guard) (*box.Box, error) {
	registry := include.OutboundRegistry()
	sbout.Register[option.StubOptions](registry, traceType, func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.StubOptions) (adapter.Outbound, error) {
		return &traceOutbound{Adapter: sbout.NewAdapter(traceType, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil), guard: guard}, nil
	})
	ctx := box.Context(context.Background(), include.InboundRegistry(), registry, include.EndpointRegistry(),
		include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	all := append([]map[string]any{{"type": traceType, "tag": traceTag}}, outbounds...)
	raw, err := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "outbounds": all,
		"route": map[string]any{"final": traceTag}})
	if err != nil {
		return nil, err
	}
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		return nil, cleanError(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return nil, cleanError(err)
	}
	return instance, nil
}

// cleanError strips sing-box's option path noise ("initialize outbound[3]: ")
// while keeping the useful message.
func cleanError(err error) error {
	message := err.Error()
	if i := strings.Index(message, "]: "); i >= 0 && strings.Contains(message[:i], "outbound[") {
		message = message[i+3:]
	}
	return errors.New(message)
}

type traceOutbound struct {
	sbout.Adapter
	guard Guard
}

func (o *traceOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP, N.NetworkUDP:
	default:
		return nil, fmt.Errorf("unsupported network %s", network)
	}
	return NetDial(ctx, N.NetworkName(network), destination.String(), o.guard)
}

func (o *traceOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := NetDial(ctx, N.NetworkUDP, destination.String(), o.guard)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// Convert renders a node as a sing-box outbound object.
func Convert(node outbound.Node) (map[string]any, error) {
	host, port, err := wire.Split(node.Server)
	if err != nil {
		return nil, errors.New("server must be host:port")
	}
	out := map[string]any{"tag": node.Name, "server": host, "server_port": port, "detour": traceTag}
	set := func(key, value string) {
		if value != "" {
			out[key] = value
		}
	}
	switch node.Type {
	case "socks5":
		out["type"], out["version"] = "socks", "5"
		set("username", node.Username)
		set("password", node.Password)
	case "http", "https":
		out["type"] = "http"
		set("username", node.Username)
		set("password", node.Password)
	case "shadowsocks":
		out["type"], out["method"], out["password"] = "shadowsocks", node.Cipher, node.Password
	case "trojan", "hysteria2", "anytls":
		out["type"], out["password"] = node.Type, node.Password
	case "vless":
		out["type"], out["uuid"] = "vless", node.UUID
	case "vmess":
		security := node.Cipher
		if security == "" {
			security = "auto"
		}
		out["type"], out["uuid"], out["security"], out["alter_id"] = "vmess", node.UUID, security, 0
	case "tuic":
		out["type"], out["uuid"] = "tuic", node.UUID
		set("password", node.Password)
	default:
		return nil, fmt.Errorf("unsupported node type %q", node.Type)
	}
	if node.UsesTLS() {
		tls := map[string]any{"enabled": true}
		if node.ServerName != "" {
			tls["server_name"] = node.ServerName
		}
		if node.CAPEM != "" {
			tls["certificate"] = node.CAPEM
		}
		if node.Type == "tuic" {
			tls["alpn"] = []string{"h3"} // what every TUIC server expects; options may override
		}
		out["tls"] = tls
	}
	if len(node.Options) != 0 {
		var extra map[string]any
		if err := json.Unmarshal(node.Options, &extra); err != nil {
			return nil, errors.New("options must be a JSON object")
		}
		for _, key := range []string{"tag", "type"} {
			if _, ok := extra[key]; ok {
				return nil, fmt.Errorf("options cannot set %q", key)
			}
		}
		if detour, ok := extra["detour"].(string); ok && detour == "" {
			delete(extra, "detour")
		}
		merge(out, extra)
	}
	return out, nil
}

func merge(destination, source map[string]any) {
	for key, value := range source {
		if child, ok := value.(map[string]any); ok {
			if existing, ok := destination[key].(map[string]any); ok {
				merge(existing, child)
				continue
			}
		}
		destination[key] = value
	}
}

// chunkConn caps write size. sing-anytls stores the frame length in 16 bits
// and silently corrupts the stream when one Write exceeds 65535 bytes.
type chunkConn struct{ net.Conn }

const maxChunk = 16 << 10

func (conn *chunkConn) Write(data []byte) (int, error) {
	written := 0
	for len(data) > 0 {
		n, err := conn.Conn.Write(data[:min(len(data), maxChunk)])
		written += n
		if err != nil {
			return written, err
		}
		data = data[n:]
	}
	return written, nil
}

func (conn *chunkConn) CloseWrite() error { return wire.CloseWrite(conn.Conn) }

// handshakeConn orders the lazy handshake of protocols that send their
// request header with the first payload (Shadowsocks, VLESS, Trojan, ...).
// sing-box's own router does this; HopWay relays both directions at once, so
// it must too. Without it, reading before the first write races the
// protocol's handshake state (sing-shadowsocks2 compares the response salt
// against a field the writer has not stored yet), and server-first protocols
// such as SSH or SMTP would wait forever for a request that is never sent.
type handshakeConn struct {
	net.Conn
	mu     sync.Mutex
	wrote  atomic.Bool
	done   chan struct{}
	closed chan struct{}
	once   sync.Once
	err    error
}

// serverFirstDelay matches sing-box's C.ReadPayloadTimeout: how long a reader
// waits for the client to speak before sending an empty request.
const serverFirstDelay = 300 * time.Millisecond

func newHandshakeConn(conn net.Conn) *handshakeConn {
	return &handshakeConn{Conn: conn, done: make(chan struct{}), closed: make(chan struct{})}
}

func (c *handshakeConn) first(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wrote.Load() {
		return c.Conn.Write(p)
	}
	n, err := c.Conn.Write(p)
	c.err = err
	c.wrote.Store(true)
	close(c.done)
	return n, err
}

func (c *handshakeConn) Write(p []byte) (int, error) {
	if c.wrote.Load() {
		return c.Conn.Write(p)
	}
	return c.first(p)
}

func (c *handshakeConn) Read(p []byte) (int, error) {
	if !c.wrote.Load() {
		timer := time.NewTimer(serverFirstDelay)
		select {
		case <-c.done:
		case <-c.closed:
			timer.Stop()
			return 0, net.ErrClosed
		case <-timer.C:
			if _, err := c.first(nil); err != nil {
				return 0, err
			}
		}
		timer.Stop()
		if c.err != nil {
			return 0, c.err
		}
	}
	return c.Conn.Read(p)
}

func (c *handshakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *handshakeConn) CloseWrite() error { return wire.CloseWrite(c.Conn) }
