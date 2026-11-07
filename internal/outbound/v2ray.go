package outbound

import (
	"errors"
	"net"

	"github.com/gofrs/uuid/v5"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"mac-proxy/internal/wire"
)

func (node *Node) prepareV2Ray() error {
	if id, err := uuid.FromString(node.UUID); err != nil || id == uuid.Nil {
		return errors.New("VLESS and VMess require a valid UUID")
	}
	if node.Type == "vless" {
		client, err := vless.NewClient(node.UUID, "", logger.NOP())
		if err == nil {
			node.v2Dial = client.DialConn
		}
		return err
	}
	cipher := node.Cipher
	if cipher == "" {
		cipher = "auto"
	}
	client, err := vmess.NewClient(node.UUID, cipher, 0)
	if err == nil {
		node.v2Dial = func(conn net.Conn, target M.Socksaddr) (net.Conn, error) {
			return client.DialConn(conn, target)
		}
	}
	return err
}

type v2RayConn struct {
	net.Conn
	transport net.Conn
}

func (conn *v2RayConn) CloseWrite() error {
	return wire.CloseWrite(conn.transport)
}

func (node Node) connectV2Ray(conn net.Conn, target string) (net.Conn, error) {
	if node.v2Dial == nil {
		return nil, errors.New("VLESS or VMess node was not validated")
	}
	stream, err := node.v2Dial(conn, M.ParseSocksaddr(target))
	if err != nil {
		return nil, err
	}
	return &v2RayConn{Conn: stream, transport: conn}, nil
}
