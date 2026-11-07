package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/httpproxy"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/socks5"
	"mac-proxy/internal/wire"
)

func tcpFixture(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func tcpIngress(t *testing.T, dial httpproxy.Dial) (string, string) {
	t.Helper()
	socks := tcpFixture(t)
	go func() {
		for {
			conn, err := socks.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = socks5.Handle(conn, socks5.DialFunc(dial))
			}()
		}
	}()
	server := httptest.NewServer(httpproxy.Handler(dial))
	t.Cleanup(server.Close)
	return socks.Addr().String(), server.Listener.Addr().String()
}

func tcpClient(t *testing.T, address string) *net.TCPConn {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	client := conn.(*net.TCPConn)
	t.Cleanup(func() { client.Close() })
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	return client
}

func requestTunnel(t *testing.T, client *net.TCPConn, inbound, target string) {
	t.Helper()
	if inbound == "socks" {
		if _, err := client.Write([]byte{5, 1, 0}); err != nil {
			t.Fatal(err)
		}
		var auth [2]byte
		if _, err := io.ReadFull(client, auth[:]); err != nil || auth != [2]byte{5, 0} {
			t.Fatalf("SOCKS negotiation: %x %v", auth, err)
		}
		address, err := wire.EncodeAddress(target)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(append([]byte{5, 1, 0}, address...)); err != nil {
			t.Fatal(err)
		}
	} else if _, err := fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
}

func readTunnelReply(t *testing.T, reader *bufio.Reader, inbound string) {
	t.Helper()
	if inbound == "socks" {
		var response [4]byte
		if _, err := io.ReadFull(reader, response[:]); err != nil || response[1] != 0 {
			t.Fatalf("SOCKS tunnel response: %x %v", response, err)
		}
		if _, err := wire.ReadAddress(reader, response[3]); err != nil {
			t.Fatal(err)
		}
		return
	}
	status, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 200 ") {
		t.Fatalf("CONNECT response: %q %v", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			return
		}
	}
}

func TestClientCancellationReleasesStalledTLSHandshakes(t *testing.T) {
	const count = endpointDialLimit
	for _, impl := range []backend.Backend{backend.Native{}, backend.Default()} {
		t.Run(impl.Name(), func(t *testing.T) {
			origin := tcpFixture(t)
			hello := make(chan error, count)
			finished := make(chan error, count)
			go func() {
				for {
					conn, err := origin.AcceptTCP()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						var header [5]byte
						_, err := io.ReadFull(conn, header[:])
						if err == nil && header[0] != 0x16 {
							err = fmt.Errorf("wanted a TLS handshake, got %x", header)
						}
						hello <- err
						_, err = io.Copy(io.Discard, conn)
						finished <- err
					}()
				}
			}()
			config := Default()
			config.Mode, config.Selected = "global", "stall"
			config.Nodes = []outbound.Node{{Name: "stall", Type: "https", Server: origin.Addr().String()}}
			core, err := New(config, impl)
			if err != nil {
				t.Fatal(err)
			}
			defer core.Close()
			socks, http := tcpIngress(t, core.Dial)
			runtime.GC()
			var heapBefore, heapHeld, heapAfter runtime.MemStats
			runtime.ReadMemStats(&heapBefore)
			baseGoroutines := runtime.NumGoroutine()
			baseFDs := countOpenDescriptors(t)
			clients := make([]*net.TCPConn, 0, count)
			defer func() {
				for _, client := range clients {
					client.Close()
				}
			}()
			const target = "fixture.test:443"
			for i := range count {
				switch i % 3 {
				case 0:
					client := tcpClient(t, socks)
					clients = append(clients, client)
					requestTunnel(t, client, "socks", target)
				case 1:
					client := tcpClient(t, http)
					clients = append(clients, client)
					requestTunnel(t, client, "connect", target)
				case 2:
					client := tcpClient(t, http)
					clients = append(clients, client)
					if _, err := io.WriteString(client, "GET http://fixture.test/a HTTP/1.1\r\nHost: fixture.test\r\n\r\n"); err != nil {
						t.Fatal(err)
					}
				}
			}
			started := time.NewTimer(3 * time.Second)
			defer started.Stop()
			for range count {
				select {
				case err := <-hello:
					if err != nil {
						t.Fatal(err)
					}
				case <-started.C:
					t.Fatal("not all clients reached the stalled TLS handshake")
				}
			}
			atPeak := runtime.NumGoroutine()
			fdsAtPeak := countOpenDescriptors(t)
			runtime.ReadMemStats(&heapHeld)
			canceled := time.Now()
			for _, client := range clients {
				_ = client.Close()
			}
			drain := time.NewTimer(time.Second)
			defer drain.Stop()
			for range count {
				select {
				case err := <-finished:
					if err != nil && !errors.Is(err, net.ErrClosed) {
						t.Fatalf("unexpected upstream read error: %v", err)
					}
				case <-drain.C:
					t.Fatal("canceled handshake did not release its upstream socket")
				}
			}
			for len(core.dialSlots["stall"].opening) != 0 || runtime.NumGoroutine() > baseGoroutines+3 {
				select {
				case <-drain.C:
					t.Fatalf("canceled clients left work behind: slots=%d goroutines=%d/%d", len(core.dialSlots["stall"].opening), runtime.NumGoroutine(), baseGoroutines)
				case <-time.After(time.Millisecond):
				}
			}
			elapsed := time.Since(canceled)
			fdsAfter := countOpenDescriptors(t)
			if baseFDs >= 0 && (fdsAtPeak < baseFDs+count || fdsAfter > baseFDs+3) {
				t.Fatalf("FD count did not rise and return after cancellation: %d → %d → %d", baseFDs, fdsAtPeak, fdsAfter)
			}
			runtime.GC()
			runtime.ReadMemStats(&heapAfter)
			t.Logf("%d handshakes closed in %s, goroutines %d → %d → %d, FDs %d → %d → %d, sampled HeapAlloc %d → %d → %d bytes",
				count, elapsed, baseGoroutines, atPeak, runtime.NumGoroutine(), baseFDs, fdsAtPeak, fdsAfter,
				heapBefore.HeapAlloc, heapHeld.HeapAlloc, heapAfter.HeapAlloc)
			if core.Status().Nodes[2].Alive != nil || core.Active() != 0 {
				t.Fatal("client cancellations changed node health or left active connections")
			}
		})
	}
}

func countOpenDescriptors(t *testing.T) int {
	t.Helper()
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		return len(entries)
	}
	lsof, err := exec.LookPath("lsof")
	if err != nil {
		return -1
	}
	output, err := exec.Command(lsof, "-nP", "-a", "-p", strconv.Itoa(os.Getpid()), "-Ff").Output()
	if err != nil {
		t.Logf("unable to sample open descriptors: %v", err)
		return -1
	}
	count := 0
	for _, line := range strings.Split(string(output), "\n") {
		if fd, ok := strings.CutPrefix(line, "f"); ok {
			if _, err := strconv.Atoi(fd); err == nil {
				count++
			}
		}
	}
	return count
}

func TestEarlyClientHalfClosePreservesTunnelPayloadAndReply(t *testing.T) {
	for _, inbound := range []string{"socks", "connect"} {
		t.Run(inbound, func(t *testing.T) {
			origin := tcpFixture(t)
			reply := make(chan error, 1)
			go func() {
				peer, err := origin.AcceptTCP()
				if err != nil {
					reply <- err
					return
				}
				defer peer.Close()
				_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
				payload, err := io.ReadAll(peer)
				if err == nil {
					_, err = fmt.Fprintf(peer, "reply: %s", payload)
				}
				reply <- err
			}()
			started, proceed := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-proceed:
				default:
					close(proceed)
				}
			}()
			socks, http := tcpIngress(t, func(ctx context.Context, _, target string) (net.Conn, error) {
				close(started)
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-proceed:
					return (&net.Dialer{}).DialContext(ctx, "tcp", target)
				}
			})
			address := socks
			if inbound == "connect" {
				address = http
			}
			client := tcpClient(t, address)
			requestTunnel(t, client, inbound, origin.Addr().String())
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("tunnel dial did not start")
			}
			if _, err := io.WriteString(client, "early payload"); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			close(proceed)
			reader := bufio.NewReader(client)
			readTunnelReply(t, reader, inbound)
			data, err := io.ReadAll(reader)
			if err != nil || string(data) != "reply: early payload" {
				t.Fatalf("early half-close lost the reply: %q %v", data, err)
			}
			if err := <-reply; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTunnelRecordsClientAndUpstreamReset(t *testing.T) {
	for _, resetAt := range []string{"client", "upstream"} {
		t.Run(resetAt, func(t *testing.T) {
			core, err := New(Default(), backend.Native{})
			if err != nil {
				t.Fatal(err)
			}
			defer core.Close()
			origin := tcpFixture(t)
			socks, _ := tcpIngress(t, core.Dial)
			client := tcpClient(t, socks)
			requestTunnel(t, client, "socks", origin.Addr().String())
			_ = origin.SetDeadline(time.Now().Add(time.Second))
			peer, err := origin.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			readTunnelReply(t, bufio.NewReader(client), "socks")
			reset := client
			if resetAt == "upstream" {
				reset = peer
			}
			if err := reset.SetLinger(0); err != nil {
				t.Fatal(err)
			}
			if err := reset.Close(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for {
				status := core.Status()
				if status.Active == 0 && len(status.Connections) == 1 {
					record := status.Connections[0]
					if record.State != "failed" || record.Stage != resetAt+"-read" ||
						!strings.Contains(record.Error, "connection reset") {
						t.Fatalf("reset reported against the wrong endpoint: %+v", record)
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatal("reset connection remained active")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestUpstreamHalfCloseStillAllowsClientUpload(t *testing.T) {
	for _, inbound := range []string{"socks", "connect"} {
		t.Run(inbound, func(t *testing.T) {
			origin := tcpFixture(t)
			uploaded := make(chan string, 1)
			serverErr := make(chan error, 1)
			go func() {
				conn, err := origin.AcceptTCP()
				if err != nil {
					serverErr <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := io.WriteString(conn, "response before upload"); err != nil {
					serverErr <- err
					return
				}
				if err := conn.CloseWrite(); err != nil {
					serverErr <- err
					return
				}
				data, err := io.ReadAll(conn)
				uploaded <- string(data)
				serverErr <- err
			}()
			socks, http := tcpIngress(t, func(ctx context.Context, _, target string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", target)
			})
			address := socks
			if inbound == "connect" {
				address = http
			}
			client := tcpClient(t, address)
			requestTunnel(t, client, inbound, origin.Addr().String())
			reader := bufio.NewReader(client)
			readTunnelReply(t, reader, inbound)
			down, err := io.ReadAll(reader)
			if err != nil || string(down) != "response before upload" {
				t.Fatalf("upstream half-close response: %q %v", down, err)
			}
			if _, err := io.WriteString(client, "upload after response EOF"); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			if got := <-uploaded; got != "upload after response EOF" {
				t.Fatalf("reverse upload after upstream half-close: %q", got)
			}
		})
	}
}
