// Package socks5 implements a local, unauthenticated SOCKS5 inbound with
// CONNECT and UDP ASSOCIATE.
package socks5

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"syscall"
	"time"

	"mac-proxy/internal/outbound"
	"mac-proxy/internal/peer"
	"mac-proxy/internal/wire"
)

const (
	version      = 5
	noAuth       = 0
	connect      = 1
	udpAssociate = 3

	addressIPv4 = 1
	addressIPv6 = 4

	replySuccess            = 0
	replyFailure            = 1
	replyNetworkUnreachable = 3
	replyHostUnreachable    = 4
	replyConnectionRefused  = 5
	replyUnsupportedCommand = 7
	replyUnsupportedAddress = 8
)

// Handle serves one SOCKS5 client. The caller owns client and closes it on return.
type DialFunc func(context.Context, string, string) (net.Conn, error)
type DialPacketFunc func(context.Context, string, string) (net.PacketConn, error)

func Handle(client *net.TCPConn, dial DialFunc) error { return HandleWithUDP(client, dial, nil) }

// HandleWithUDP serves one client; dialPacket enables UDP ASSOCIATE.
func HandleWithUDP(client *net.TCPConn, dial DialFunc, dialPacket DialPacketFunc) error {
	return HandleWithUDPTimeout(client, dial, dialPacket, udpSessionIdle)
}

// HandleWithUDPTimeout serves one client with a custom UDP session idle timeout.
func HandleWithUDPTimeout(client *net.TCPConn, dial DialFunc, dialPacket DialPacketFunc, idle time.Duration) error {
	if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if err := negotiate(client); err != nil {
		return fmt.Errorf("negotiate: %w", err)
	}

	command, target, reply, err := readRequest(client, dialPacket != nil)
	if err == nil && command == udpAssociate {
		return associate(client, target, dialPacket, idle)
	}
	if err != nil {
		if reply != replySuccess {
			return errors.Join(err, writeReply(client, reply, nil))
		}
		return err
	}

	reader := bufio.NewReader(client)
	ctx := peer.With(context.Background(), client.RemoteAddr(), client.LocalAddr())
	upstream, err := wire.DialWithClient(ctx, client, reader, func(ctx context.Context) (net.Conn, error) {
		return dial(ctx, "SOCKS5", target)
	})
	if err != nil {
		return errors.Join(
			fmt.Errorf("dial %s: %w", target, err),
			writeReply(client, dialFailureReply(err), nil),
		)
	}
	defer upstream.Close()

	bound, _ := upstream.LocalAddr().(*net.TCPAddr)
	if err := writeReply(client, replySuccess, bound); err != nil {
		return err
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return err
	}
	var downstream net.Conn = client
	if reader.Buffered() > 0 {
		downstream = &wire.BufferedConn{Conn: client, Reader: reader}
	}
	wire.Relay(downstream, upstream)
	return nil
}

func negotiate(client io.ReadWriter) error {
	var header [2]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		return err
	}
	if header[0] != version {
		return fmt.Errorf("unsupported SOCKS version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return err
	}
	if !slices.Contains(methods, noAuth) {
		_, err := client.Write([]byte{version, 0xff})
		return errors.Join(errors.New("client did not offer no-auth method"), err)
	}
	_, err := client.Write([]byte{version, noAuth})
	return err
}

func readRequest(reader io.Reader, allowUDP bool) (command byte, target string, reply byte, err error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, "", replySuccess, err
	}
	if header[0] != version || header[2] != 0 {
		return 0, "", replyFailure, errors.New("invalid request header")
	}
	command = header[1]
	if command != connect && !(command == udpAssociate && allowUDP) {
		return command, "", replyUnsupportedCommand, fmt.Errorf("unsupported command %d", header[1])
	}

	target, err = wire.ReadAddress(reader, header[3])
	if errors.Is(err, wire.ErrAddressType) {
		return command, "", replyUnsupportedAddress, err
	}
	if err != nil {
		return command, "", replyFailure, err
	}
	return command, target, replySuccess, nil
}

func writeReply(writer io.Writer, reply byte, bound *net.TCPAddr) error {
	addressType := byte(addressIPv4)
	ip := net.IPv4zero.To4()
	var port uint16
	if bound != nil {
		ip = bound.IP.To4()
		if ip == nil {
			addressType = addressIPv6
			ip = bound.IP.To16()
		}
		port = uint16(bound.Port)
	}

	response := []byte{version, reply, 0, addressType}
	response = append(response, ip...)
	response = binary.BigEndian.AppendUint16(response, port)
	_, err := writer.Write(response)
	return err
}

func dialFailureReply(err error) byte {
	var dnsError *net.DNSError
	switch {
	case errors.Is(err, outbound.ErrRejected):
		return 2
	case errors.Is(err, syscall.ECONNREFUSED):
		return replyConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return replyNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH), errors.As(err, &dnsError):
		return replyHostUnreachable
	default:
		return replyFailure
	}
}
