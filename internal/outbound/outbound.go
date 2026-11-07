package outbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"mac-proxy/internal/wire"
)

var ErrRejected = errors.New("blocked by routing policy")

// PrepareNative validates a node for the built-in protocol implementation and
// caches the state it needs. The built-in implementation has no third-party
// protocol code beyond VLESS/VMess and is kept for licence-sensitive builds.
func (node *Node) PrepareNative() error {
	if err := node.Validate(); err != nil {
		return err
	}
	if len(node.Options) != 0 {
		return errors.New("extra options need the sing-box backend")
	}
	if node.CAPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("load system trust: %w", err)
		}
		roots.AppendCertsFromPEM([]byte(node.CAPEM))
		node.rootCAs = roots
	}
	switch node.Type {
	case "socks5", "http", "https", "trojan":
	case "shadowsocks":
		if node.Password == "" || cipherSize(node.Cipher) == 0 {
			return errors.New("Shadowsocks requires a password and aes-128-gcm or aes-256-gcm")
		}
	case "vless", "vmess":
		return node.prepareV2Ray()
	default:
		return fmt.Errorf("node type %q needs the sing-box backend", node.Type)
	}
	return nil
}

func (node Node) Dial(ctx context.Context, target string, dial func(context.Context, string) (net.Conn, error)) (net.Conn, error) {
	raw, err := dial(ctx, node.Server)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()

	var conn net.Conn = raw
	if node.UsesTLS() {
		name := node.ServerName
		if name == "" {
			name, _, _ = net.SplitHostPort(node.Server)
		}
		secure := tls.Client(raw, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12, RootCAs: node.rootCAs})
		if err := secure.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = secure
	}
	switch node.Type {
	case "socks5":
		err = node.socksConnect(conn, target)
	case "http", "https":
		conn, err = node.httpConnect(conn, target)
	case "trojan":
		address, addressErr := wire.EncodeAddress(target)
		if addressErr != nil {
			return nil, addressErr
		}
		hash := sha256.Sum224([]byte(node.Password))
		header := hex.AppendEncode(nil, hash[:])
		header = append(header, '\r', '\n', 1)
		header = append(header, address...)
		header = append(header, '\r', '\n')
		_, err = conn.Write(header)
	case "shadowsocks":
		conn, err = node.shadowsocksConnect(conn, target)
	case "vless", "vmess":
		conn, err = node.connectV2Ray(conn, target)
	}
	if err != nil {
		return nil, err
	}
	if !stop() {
		return nil, ctx.Err()
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	success = true
	return conn, nil
}

func (node Node) socksConnect(conn net.Conn, target string) error {
	method := byte(0)
	if node.Username != "" {
		method = 2
	}
	if _, err := conn.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	var response [4]byte
	if _, err := io.ReadFull(conn, response[:2]); err != nil {
		return err
	}
	if response[0] != 5 || response[1] != method {
		return errors.New("upstream SOCKS5 did not accept authentication method")
	}
	if method == 2 {
		auth := append([]byte{1, byte(len(node.Username))}, node.Username...)
		auth = append(auth, byte(len(node.Password)))
		auth = append(auth, node.Password...)
		if _, err := conn.Write(auth); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, response[:2]); err != nil {
			return err
		}
		if response[0] != 1 || response[1] != 0 {
			return errors.New("upstream SOCKS5 authentication failed")
		}
	}
	address, err := wire.EncodeAddress(target)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append([]byte{5, 1, 0}, address...)); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response[0] != 5 || response[1] != 0 || response[2] != 0 {
		return fmt.Errorf("upstream SOCKS5 CONNECT failed (code %d)", response[1])
	}
	_, err = wire.ReadAddress(conn, response[3])
	return err
}

func (node Node) httpConnect(conn net.Conn, target string) (net.Conn, error) {
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Host: target}, Host: target, Header: make(http.Header)}
	if node.Username != "" {
		request.SetBasicAuth(node.Username, node.Password)
		request.Header.Set("Proxy-Authorization", request.Header.Get("Authorization"))
		request.Header.Del("Authorization")
	}
	if err := request.Write(conn); err != nil {
		return nil, err
	}
	// Read MIME headers with a bounded reader, preserving any buffered tunnel payload.
	limit := &io.LimitedReader{R: conn, N: 32 << 10}
	reader := bufio.NewReader(limit)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, errors.New("invalid upstream CONNECT response")
	}
	if response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("upstream CONNECT returned HTTP %d", response.StatusCode)
	}
	buffered := make([]byte, reader.Buffered())
	if _, err := io.ReadFull(reader, buffered); err != nil {
		return nil, err
	}
	reader.Reset(io.MultiReader(bytes.NewReader(buffered), conn))
	return &wire.BufferedConn{Conn: conn, Reader: reader}, nil
}
