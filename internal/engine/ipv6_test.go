package engine

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/socks5"
)

func TestIPv6OnlyNodeReachesIPv4TargetAndReportsRefusal(t *testing.T) {
	proxy, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer proxy.Close()
	service, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	go func() {
		for {
			conn, err := proxy.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				socks5.Handle(conn, func(ctx context.Context, _, target string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "tcp4", target)
				})
			}()
		}
	}()
	go func() {
		for {
			conn, err := service.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	implementations := []backend.Backend{backend.Default()}
	if implementations[0].Name() != (backend.Native{}).Name() {
		implementations = append(implementations, backend.Native{})
	}
	for _, impl := range implementations {
		t.Run(impl.Name(), func(t *testing.T) {
			config := Default()
			config.Mode, config.Selected = "global", "v6-only"
			config.Nodes = []outbound.Node{{Name: "v6-only", Type: "socks5", Server: proxy.Addr().String()}}
			core, err := New(config, impl)
			if err != nil {
				t.Fatal(err)
			}
			defer core.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			target := service.Addr().String()
			conn, err := core.Dial(ctx, "SOCKS5", target)
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(time.Second))
			defer conn.Close()
			if _, err := conn.Write([]byte("dual")); err != nil {
				t.Fatal(err)
			}
			var echo [4]byte
			if _, err := io.ReadFull(conn, echo[:]); err != nil || string(echo[:]) != "dual" {
				t.Fatalf("IPv6 node to IPv4 target: %q, %v", echo, err)
			}
			conn.Close()
			closed, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			refused := closed.Addr().String()
			closed.Close()
			if conn, err := core.Dial(ctx, "SOCKS5", refused); err == nil {
				conn.Close()
				t.Fatal("closed IPv4 service unexpectedly connected")
			}
			for _, record := range core.Status().Connections {
				if record.Target == refused && record.Via == "v6-only" && record.State == "failed" &&
					(strings.Contains(record.Error, "code 5") || strings.Contains(record.Error, "code=5") ||
						strings.Contains(strings.ToLower(record.Error), "refused")) {
					return
				}
			}
			t.Fatalf("missing useful refusal diagnostic: %+v", core.Status().Connections)
		})
	}
}
