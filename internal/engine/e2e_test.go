//go:build !hopway_native

package engine

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
)

const testUUID = "ccc641c2-e296-455c-9f8e-8d13a9b02976"

type fixture struct {
	certPEM, keyPEM string
	echo            string // TCP echo target
	ports           map[string]int
}

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).Port
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func selfSigned(t *testing.T, name string) (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func echoServer(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// startServer runs a sing-box instance with one inbound per protocol.
func startServer(t *testing.T) (*fixture, map[string]outbound.Node) {
	f := &fixture{ports: map[string]int{}}
	f.certPEM, f.keyPEM = selfSigned(t, "hopway.test")
	f.echo = echoServer(t)

	// REALITY borrows a real TLS server's handshake; use a local one.
	realityCert, realityKey := selfSigned(t, "decoy.test")
	pair, _ := tls.X509KeyPair([]byte(realityCert), []byte(realityKey))
	decoy, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { decoy.Close() })
	go func() {
		for {
			conn, err := decoy.Accept()
			if err != nil {
				return
			}
			go func() { conn.(*tls.Conn).Handshake(); time.Sleep(time.Second); conn.Close() }()
		}
	}()
	private, _ := ecdh.X25519().GenerateKey(rand.Reader)
	privateKey := base64.RawURLEncoding.EncodeToString(private.Bytes())
	publicKey := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	ss2022 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

	tlsServer := map[string]any{"enabled": true, "server_name": "hopway.test", "certificate": f.certPEM, "key": f.keyPEM}
	quicTLS := map[string]any{"enabled": true, "server_name": "hopway.test", "certificate": f.certPEM, "key": f.keyPEM, "alpn": []string{"h3"}}
	inbounds := []map[string]any{
		{"type": "shadowsocks", "tag": "ss", "method": "2022-blake3-aes-128-gcm", "password": ss2022},
		{"type": "trojan", "tag": "trojan", "users": []any{map[string]any{"password": "secret"}}, "tls": tlsServer},
		{"type": "vless", "tag": "vless-ws", "users": []any{map[string]any{"uuid": testUUID}}, "tls": tlsServer,
			"transport": map[string]any{"type": "ws", "path": "/ws"}},
		{"type": "vmess", "tag": "vmess-grpc", "users": []any{map[string]any{"uuid": testUUID}}, "tls": tlsServer,
			"transport": map[string]any{"type": "grpc", "service_name": "svc"}},
		{"type": "vless", "tag": "reality", "users": []any{map[string]any{"uuid": testUUID, "flow": "xtls-rprx-vision"}},
			"tls": map[string]any{"enabled": true, "server_name": "decoy.test", "reality": map[string]any{
				"enabled": true, "private_key": privateKey, "short_id": []string{"0123abcd"},
				"handshake": map[string]any{"server": "127.0.0.1", "server_port": decoy.Addr().(*net.TCPAddr).Port}}}},
		{"type": "hysteria2", "tag": "hy2", "users": []any{map[string]any{"password": "secret"}}, "tls": quicTLS},
		{"type": "tuic", "tag": "tuic", "users": []any{map[string]any{"uuid": testUUID, "password": "secret"}}, "tls": quicTLS},
		{"type": "anytls", "tag": "anytls", "users": []any{map[string]any{"password": "secret"}}, "tls": tlsServer},
	}
	for _, inbound := range inbounds {
		network := "tcp"
		if inbound["type"] == "hysteria2" || inbound["type"] == "tuic" {
			network = "udp"
		}
		port := freePort(t, network)
		inbound["listen"], inbound["listen_port"] = "127.0.0.1", port
		f.ports[inbound["tag"].(string)] = port
	}
	raw, _ := json.Marshal(map[string]any{"log": map[string]any{"disabled": true}, "inbounds": inbounds,
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}})
	ctx := include.Context(context.Background())
	options, err := sjson.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })

	at := func(tag string) string { return fmt.Sprintf("localhost:%d", f.ports[tag]) }
	opt := func(v any) json.RawMessage { data, _ := json.Marshal(v); return data }
	nodes := map[string]outbound.Node{
		"ss2022": {Name: "ss2022", Type: "shadowsocks", Server: at("ss"), Cipher: "2022-blake3-aes-128-gcm", Password: ss2022},
		"trojan": {Name: "trojan", Type: "trojan", Server: at("trojan"), Password: "secret", ServerName: "hopway.test", CAPEM: f.certPEM},
		"vless-ws": {Name: "vless-ws", Type: "vless", Server: at("vless-ws"), UUID: testUUID, TLS: true, ServerName: "hopway.test",
			CAPEM: f.certPEM, Options: opt(map[string]any{"transport": map[string]any{"type": "ws", "path": "/ws"}})},
		"vmess-grpc": {Name: "vmess-grpc", Type: "vmess", Server: at("vmess-grpc"), UUID: testUUID, TLS: true, ServerName: "hopway.test",
			CAPEM: f.certPEM, Options: opt(map[string]any{"transport": map[string]any{"type": "grpc", "service_name": "svc"}})},
		"reality": {Name: "reality", Type: "vless", Server: at("reality"), UUID: testUUID, TLS: true, ServerName: "decoy.test",
			Options: opt(map[string]any{"flow": "xtls-rprx-vision", "tls": map[string]any{
				"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{"enabled": true, "public_key": publicKey, "short_id": "0123abcd"}}})},
		"hy2":    {Name: "hy2", Type: "hysteria2", Server: at("hy2"), Password: "secret", ServerName: "hopway.test", CAPEM: f.certPEM},
		"tuic":   {Name: "tuic", Type: "tuic", Server: at("tuic"), UUID: testUUID, Password: "secret", ServerName: "hopway.test", CAPEM: f.certPEM},
		"anytls": {Name: "anytls", Type: "anytls", Server: at("anytls"), Password: "secret", ServerName: "hopway.test", CAPEM: f.certPEM},
	}
	return f, nodes
}

func roundTrip(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	written := make(chan error, 1)
	go func() { _, err := conn.Write([]byte(payload)); written <- err }()
	defer func() {
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}()
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != payload {
		n := 0
		for n < len(buffer) && buffer[n] == payload[n] {
			n++
		}
		t.Fatalf("echo mismatch at byte %d of %d: %v", n, len(payload), err)
	}
}

func TestProtocolsInterop(t *testing.T) {
	f, nodes := startServer(t)
	var config Config = Default()
	for _, node := range nodes {
		config.Nodes = append(config.Nodes, node)
	}
	config.Mode, config.Selected = "global", "DIRECT"
	core, err := New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	for name := range nodes {
		t.Run(name, func(t *testing.T) {
			if err := core.SetPolicy(Policy{Mode: "global", Selected: name}); err != nil {
				t.Fatal(err)
			}
			conn, err := core.Dial(context.Background(), "test", f.echo)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip(t, conn, "hello "+name)
			roundTrip(t, conn, strings.Repeat("x", 64<<10)) // larger than one frame
			conn.Close()
			record := core.Status().Connections
			last := record[len(record)-1]
			if last.State != "closed" || last.Via != name || last.Server == "" {
				t.Fatalf("unexpected record %+v", last)
			}
		})
	}
}

func TestDiagnosticsAndFailover(t *testing.T) {
	f, nodes := startServer(t)
	bad := nodes["trojan"]
	bad.Name, bad.Password = "wrong-password", "nope"
	dead := nodes["trojan"]
	dead.Name, dead.Server = "dead", fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp"))
	badCert := nodes["trojan"]
	badCert.Name, badCert.CAPEM = "bad-cert", ""
	noDNS := nodes["trojan"]
	noDNS.Name, noDNS.Server = "no-dns", "does-not-exist.invalid:443"
	config := Default()
	config.Nodes = []outbound.Node{nodes["trojan"], bad, dead, badCert, noDNS}
	config.Groups = []Group{{Name: "Auto", Type: GroupFallback, Members: []string{"dead", "trojan"}}}
	config.Rules = []Rule{{Type: RuleMatch, Via: "Auto"}}
	core, err := New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	// Failover: the first member refuses connections, the second works.
	conn, err := core.Dial(context.Background(), "test", f.echo)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, conn, "failover")
	conn.Close()
	status := core.Status()
	last := status.Connections[len(status.Connections)-1]
	if last.Via != "trojan" || last.Attempts != 2 || len(last.Route) != 1 || last.Route[0] != "Auto" {
		t.Fatalf("failover record %+v", last)
	}
	// The dead node is now known bad, so the next dial goes straight to trojan.
	conn, err = core.Dial(context.Background(), "test", f.echo)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	status = core.Status()
	if last := status.Connections[len(status.Connections)-1]; last.Attempts != 1 {
		t.Fatalf("expected passive health to skip the dead node: %+v", last)
	}

	expect := map[string]string{"dead": "connect", "bad-cert": "handshake", "no-dns": "dns", "wrong-password": "upstream"}
	for name, stage := range expect {
		core.SetPolicy(Policy{Mode: "global", Selected: name})
		conn, err := core.Dial(context.Background(), "test", f.echo)
		if err == nil {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			conn.Write([]byte("ping"))
			io.ReadAll(conn)
			conn.Close()
		}
		status := core.Status()
		last := status.Connections[len(status.Connections)-1]
		if last.Via != name || last.Stage != stage || last.Error == "" {
			t.Errorf("%s: want stage %s, got %+v", name, stage, last)
		}
	}
}

func TestProbeAndURLTest(t *testing.T) {
	_, nodes := startServer(t)
	target := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	go target.Serve(listener)
	defer target.Close()
	dead := nodes["trojan"]
	dead.Name, dead.Server = "dead", fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp"))
	config := Default()
	config.Nodes = []outbound.Node{dead, nodes["hy2"], nodes["ss2022"]}
	config.Groups = []Group{{Name: "Fast", Type: GroupURLTest, Members: []string{"dead", "hy2", "ss2022"}}}
	config.Health = &Health{URL: "http://" + listener.Addr().String() + "/generate_204"}
	config.Mode, config.Selected = "global", "Fast"
	core, err := New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	core.Probe(context.Background(), nil)
	status := core.Status()
	alive := map[string]bool{}
	for _, node := range status.Nodes {
		if node.Alive != nil {
			alive[node.Name] = *node.Alive
		}
	}
	if alive["dead"] || !alive["hy2"] || !alive["ss2022"] {
		t.Fatalf("probe results %+v", status.Nodes)
	}
	if now := status.Groups[0].Now; now != "hy2" && now != "ss2022" {
		t.Fatalf("url-test picked %q", now)
	}
}

// A target that speaks first (SSH, SMTP) must work through lazy-handshake
// protocols even though the client has not written anything yet.
func TestServerFirstTarget(t *testing.T) {
	_, nodes := startServer(t)
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-test\r\n"))
			time.Sleep(time.Second)
			conn.Close()
		}
	}()
	config := Default()
	for _, name := range []string{"ss2022", "trojan", "vless-ws", "reality", "anytls"} {
		config.Nodes = append(config.Nodes, nodes[name])
	}
	config.Mode, config.Selected = "global", "DIRECT"
	core, err := New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	for _, node := range config.Nodes {
		t.Run(node.Name, func(t *testing.T) {
			core.SetPolicy(Policy{Mode: "global", Selected: node.Name})
			conn, err := core.Dial(context.Background(), "test", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			banner := make([]byte, 14)
			if _, err := io.ReadFull(conn, banner); err != nil || string(banner) != "SSH-2.0-test\r\n" {
				t.Errorf("%s: banner %q, %v", node.Name, banner, err)
			}
			conn.Close()
		})
	}
}
