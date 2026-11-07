package engine

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/trace"
)

func diagnosticBackends() []backend.Backend {
	native := backend.Native{}
	current := backend.Default()
	if current.Name() == native.Name() {
		return []backend.Backend{native}
	}
	return []backend.Backend{native, current}
}

func diagnosticCertificate(t *testing.T, name string, before, after time.Time) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(17), DNSNames: []string{name}, NotBefore: before, NotAfter: after,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func runDiagnosticNode(t *testing.T, impl backend.Backend, node outbound.Node) *Engine {
	t.Helper()
	cfg := Default()
	cfg.Nodes = []outbound.Node{node}
	cfg.Mode, cfg.Selected = "global", node.Name
	cfg.Health = &Health{URL: "http://target.test/probe"}
	core, err := New(cfg, impl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	return core
}

func TestTLSCertificateDiagnosticsFromRealHandshake(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		code, serverName string
		expires          time.Time
	}{
		{"tls-expired", "proxy.test", now.Add(-time.Hour)},
		{"tls-hostname", "other.test", now.Add(time.Hour)},
	} {
		t.Run(test.code, func(t *testing.T) {
			pair, root := diagnosticCertificate(t, "proxy.test", now.Add(-2*time.Hour), test.expires)
			listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(time.Second))
						_ = conn.(*tls.Conn).Handshake()
					}()
				}
			}()
			for _, impl := range diagnosticBackends() {
				t.Run(impl.Name(), func(t *testing.T) {
					core := runDiagnosticNode(t, impl, outbound.Node{
						Name: "tls", Type: "https", Server: listener.Addr().String(), ServerName: test.serverName, CAPEM: root,
					})
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					if conn, err := core.Dial(ctx, "fixture", "target.test:443"); err == nil {
						conn.Close()
						t.Fatal("invalid certificate established a proxy connection")
					}
					record := core.Status().Connections[0]
					if record.FailureCode != test.code || record.Stage != trace.StageHandshake || len(record.Failures) != 1 {
						t.Fatalf("incorrect certificate diagnosis: %+v", record)
					}
				})
			}
		})
	}
}

func TestProxyAuthenticationAndUpstreamTextAreSafe(t *testing.T) {
	const user = "fixture-proxy-user"
	const secret = "fixture-proxy-secret"
	for _, test := range []struct{ typ, want string }{{"socks5", "proxy-auth"}, {"http", "handshake-failed"}} {
		t.Run(test.typ, func(t *testing.T) {
			server := tcpFixture(t)
			go func() {
				for {
					conn, err := server.AcceptTCP()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(2 * time.Second))
						if test.typ == "http" {
							scanner := bufio.NewScanner(conn)
							for scanner.Scan() && scanner.Text() != "" {
							}
							io.WriteString(conn, "HTTP/1.1 502 "+secret+"\r\nContent-Length: 0\r\n\r\n")
							return
						}
						var greeting [2]byte
						if _, err := io.ReadFull(conn, greeting[:]); err != nil {
							return
						}
						if _, err := io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
							return
						}
						conn.Write([]byte{5, 2})
						if _, err := io.ReadFull(conn, greeting[:]); err != nil {
							return
						}
						if _, err := io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
							return
						}
						if _, err := io.ReadFull(conn, greeting[:1]); err != nil {
							return
						}
						if _, err := io.CopyN(io.Discard, conn, int64(greeting[0])); err == nil {
							conn.Write([]byte{1, 1})
						}
					}()
				}
			}()
			for _, impl := range diagnosticBackends() {
				t.Run(impl.Name(), func(t *testing.T) {
					core := runDiagnosticNode(t, impl, outbound.Node{
						Name: "fixture", Type: test.typ, Server: server.Addr().String(), Username: user, Password: secret,
					})
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					conn, err := core.Dial(ctx, "fixture", "target.test:443")
					if err == nil {
						conn.Close()
						t.Fatal("failing proxy was accepted")
					}
					_, ingress := tcpIngress(t, core.Dial)
					client := tcpClient(t, ingress)
					defer client.Close()
					requestTunnel(t, client, "connect", "target.test:443")
					if line, err := bufio.NewReader(client).ReadString('\n'); err != nil || !strings.Contains(line, "502") {
						t.Fatalf("local proxy response: %q, %v", line, err)
					}
					var probe ProbeResult
					if err := core.ProbeResults(ctx, []string{"fixture"}, func(result ProbeResult) error { probe = result; return nil }); err != nil {
						t.Fatal(err)
					}
					status := core.Status()
					record := status.Connections[0]
					node := status.Nodes[2]
					if record.FailureCode != test.want || node.FailureCode != probe.FailureCode ||
						node.FailureStage != probe.FailureStage || node.HealthAt != probe.CheckedAt ||
						node.ProbeTarget != probe.Target || probe.FailureCode != test.want {
						t.Fatalf("inconsistent runtime diagnostics: %+v %+v %+v", record, node, probe)
					}
					payload, _ := json.Marshal([]any{status, probe, err.Error()})
					if strings.Contains(string(payload), user) || strings.Contains(string(payload), secret) {
						t.Fatal("upstream diagnostics exposed proxy credentials")
					}
				})
			}
		})
	}
}

func TestConfiguredAttemptsAndSafeFailureChainUnderBurst(t *testing.T) {
	cfg := Default()
	cfg.Mode, cfg.Selected, cfg.MaxDialAttempts = "global", "dns", 2
	cfg.Nodes = []outbound.Node{
		{Name: "dns", Type: "socks5", Server: "127.0.0.1:1122"},
		{Name: "socket", Type: "socks5", Server: "127.0.0.1:1123"},
		{Name: "extra", Type: "socks5", Server: "127.0.0.1:1124"},
	}
	core, err := New(cfg, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	core.mu.Lock()
	core.groups["fallback"] = &group{Group: Group{Name: "fallback", Type: GroupFallback, Members: []string{"dns", "socket", "extra"}}}
	for _, name := range []string{"dns", "socket", "extra"} {
		core.health[name] = &nodeHealth{checked: time.Now()}
	}
	core.mu.Unlock()
	if err := core.SetPolicy(Policy{Mode: "global", Selected: "fallback"}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	mk := func(stage string, failure error) backend.Dialer {
		return backend.DialerFunc(func(ctx context.Context, _ string) (net.Conn, error) {
			calls.Add(1)
			trace.From(ctx).Dial("fixture", 0, 0, stage)
			return nil, failure
		})
	}
	core.dialers["dns"] = mk(trace.StageDNS, &net.DNSError{IsNotFound: true, Name: "secret-as-host"})
	core.dialers["socket"] = mk(trace.StageConnect, errors.New("secret-as-socket-error"))
	core.dialers["extra"] = mk(trace.StageHandshake, errors.New("unexpected third attempt"))
	const burst = 20
	var wait sync.WaitGroup
	for range burst {
		wait.Go(func() { _, _ = core.Dial(context.Background(), "fixture", "target.test:443") })
	}
	wait.Wait()
	if calls.Load() != 2*burst {
		t.Fatalf("configuration allowed 2 attempts, got %d total", calls.Load())
	}
	for _, record := range core.Status().Connections {
		if len(record.Failures) != 2 || record.Failures[0].Code != "dns-not-found" ||
			record.Failures[1].Code != "connect-failed" || record.Attempts != 2 {
			t.Fatalf("missing ordered causes: %+v", record)
		}
		raw, _ := json.Marshal(record)
		if strings.Contains(string(raw), "secret-as-") {
			t.Fatal("diagnostic copied untrusted text")
		}
	}
}
