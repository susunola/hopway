package outbound

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const fixtureUUID = "ccc641c2-e296-455c-9f8e-8d13a9b02976"

type echoV2Ray struct{ target chan string }

func (server echoV2Ray) NewConnectionEx(_ context.Context, conn net.Conn, _, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	server.target <- destination.String()
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(conn, buffer); err == nil {
		conn.Write(buffer)
	}
}

func (echoV2Ray) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	conn.Close()
}

func TestV2RayTCP(t *testing.T) {
	for _, kind := range []string{"vless", "vmess"} {
		t.Run(kind, func(t *testing.T) {
			handler := echoV2Ray{target: make(chan string, 1)}
			var accept func(context.Context, net.Conn, M.Socksaddr, N.CloseHandlerFunc) error
			if kind == "vless" {
				server := vless.NewService[string](logger.NOP(), handler)
				server.UpdateUsers([]string{"fixture"}, []string{fixtureUUID}, []string{""})
				accept = server.NewConnection
			} else {
				server := vmess.NewService[string](handler)
				if err := server.UpdateUsers([]string{"fixture"}, []string{fixtureUUID}, []int{0}); err != nil {
					t.Fatal(err)
				}
				accept = server.NewConnection
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					accept(ctx, conn, M.Socksaddr{}, nil)
				}
			}()
			node := Node{Type: kind, Server: listener.Addr().String(), UUID: fixtureUUID}
			if err := node.PrepareNative(); err != nil {
				t.Fatal(err)
			}
			conn, err := node.Dial(ctx, "example.test:443", func(ctx context.Context, target string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", target)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 4)
			if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "ping" {
				t.Fatalf("tunnel response %q, %v", buffer, err)
			}
			if target := <-handler.target; target != "example.test:443" {
				t.Fatalf("unexpected destination %s", target)
			}
		})
	}
}
