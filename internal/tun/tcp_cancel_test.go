//go:build !hopway_native && (darwin || linux)

package tun

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestTUNClientCloseCancelsPendingDial(t *testing.T) {
	opts := Options{}
	opts.defaults()
	entered := make(chan struct{})
	service := &Service{
		fake: NewFakeIP(opts.FakeRange),
		dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	client, ingress := net.Pipe()
	defer client.Close()
	defer ingress.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go service.NewConnectionEx(ctx, ingress, M.ParseSocksaddr("127.0.0.1:10000"), M.ParseSocksaddr("fixture.test:443"),
		func(err error) { result <- err })
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("dial did not start")
	}
	client.Close()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("close returned %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TUN dial continued after the ingress closed")
	}
}
