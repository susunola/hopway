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

	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/wire"
)

var ErrRejected = errors.New("blocked by routing policy")

type Node struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Server     string `json:"server"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	ServerName string `json:"serverName,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	CAPEM      string `json:"caPEM,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	TLS        bool   `json:"tls,omitempty"`
	// Subscription names the provider this node was imported from; empty for hand-written nodes.
	Subscription string `json:"subscription,omitempty"`
	rootCAs      *x509.CertPool
	v2Dial       func(net.Conn, M.Socksaddr) (net.Conn, error)
}

func (node *Node) Validate() error {
	if _, _, err := wire.Split(node.Server); err != nil {
		return errors.New("server must be host:port")
	}
	if node.CAPEM != "" {
		if !node.usesTLS() {
			return errors.New("caPEM requires TLS")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("load system trust: %w", err)
		}
		if !roots.AppendCertsFromPEM([]byte(node.CAPEM)) {
			return errors.New("caPEM must contain a valid PEM certificate")
		}
		node.rootCAs = roots
	}
	switch node.Type {
	case "socks5":
		if (node.Username == "") != (node.Password == "") || len(node.Username) > 255 || len(node.Password) > 255 {
			return errors.New("SOCKS5 credentials must both be present and at most 255 bytes")
		}
	case "http", "https":
		if node.Password != "" && node.Username == "" {
			return errors.New("HTTP proxy authentication requires a username")
		}
	case "trojan":
		if node.Password == "" {
			return errors.New("Trojan requires a password")
		}
	case "shadowsocks":
		if node.Password == "" || cipherSize(node.Cipher) == 0 {
			return errors.New("Shadowsocks requires a password and aes-128-gcm or aes-256-gcm")
		}
	case "vless", "vmess":
		return node.prepareV2Ray()
	default:
		return fmt.Errorf("unsupported node type %q", node.Type)
	}
	return nil
}

func (node Node) usesTLS() bool {
	return node.Type == "https" || node.Type == "trojan" || ((node.Type == "vless" || node.Type == "vmess") && node.TLS)
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
	if node.usesTLS() {
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
