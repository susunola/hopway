//go:build darwin || linux

package wire

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func localTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remote, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { remote.Close() })
	local, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { local.Close() })
	return remote, local
}

type stalledRelayWrite struct {
	net.Conn
	started chan struct{}
	failure chan *RelayError
}

func (s stalledRelayWrite) Write(data []byte) (int, error) {
	close(s.started)
	return s.Conn.Write(data)
}

func (s stalledRelayWrite) RecordRelayError(err *RelayError) { s.failure <- err }

func TestRelayDetectsResetDuringBlockedUpload(t *testing.T) {
	client, ingress := localTCPPair(t)
	upstream, origin := net.Pipe()
	defer upstream.Close()
	defer origin.Close()
	stall := stalledRelayWrite{upstream, make(chan struct{}), make(chan *RelayError, 1)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		Relay(ingress, stall)
	}()
	if _, err := client.Write([]byte("upload while origin is blocked")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stall.started:
	case <-time.After(2 * time.Second):
		t.Fatal("upload never reached the blocked writer")
	}
	if err := client.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the reset did not interrupt the blocked upload")
	}
	select {
	case failure := <-stall.failure:
		if failure.Endpoint != "client" || failure.Operation != "read" || !errors.Is(failure.Err, syscall.ECONNRESET) {
			t.Fatalf("unexpected failure: %+v", failure)
		}
	default:
		t.Fatal("the client reset was not recorded")
	}
}

func TestFullDialBufferDistinguishesResetAndFIN(t *testing.T) {
	for _, scenario := range []string{"reset", "FIN"} {
		t.Run(scenario, func(t *testing.T) {
			client, ingress := localTCPPair(t)
			reader := bufio.NewReaderSize(ingress, 64)
			payload := bytes.Repeat([]byte{0x37}, reader.Size())
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Peek(len(payload)); err != nil {
				t.Fatal(err)
			}
			if scenario == "reset" {
				if err := client.SetLinger(0); err != nil {
					t.Fatal(err)
				}
				client.Close()
			} else if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			upstream, origin := net.Pipe()
			defer upstream.Close()
			defer origin.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := DialWithClient(ctx, ingress, reader, func(ctx context.Context) (net.Conn, error) {
				if scenario == "reset" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				timer := time.NewTimer(2 * tcpFailureInterval)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-timer.C:
					return upstream, nil
				}
			})
			if scenario == "reset" {
				if conn != nil || !errors.Is(err, context.Canceled) {
					t.Fatalf("reset failed to cancel pending dial: %v", err)
				}
				return
			}
			if conn != upstream || err != nil {
				t.Fatalf("the clean FIN canceled dialing: %v", err)
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(reader, received); err != nil || !bytes.Equal(received, payload) {
				t.Fatalf("read-ahead payload was changed: %v", err)
			}
		})
	}
}
