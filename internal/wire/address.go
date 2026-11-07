package wire

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var ErrAddressType = errors.New("unsupported address type")

// IsScopedLinkLocal identifies an IPv6 link-local address with an explicit
// interface zone. The zone is meaningful only on the machine that set it.
func IsScopedLinkLocal(addr netip.Addr) bool {
	return addr.Is6() && addr.IsLinkLocalUnicast() && addr.Zone() != ""
}

func Split(target string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 || host == "" || strings.ContainsAny(host, "/\\\r\n\t \x00") {
		return "", 0, errors.New("invalid destination host or port")
	}
	return host, uint16(number), nil
}

// EncodeAddress uses the common SOCKS5 address layout, including the port.
func EncodeAddress(target string) ([]byte, error) {
	host, port, err := Split(target)
	if err != nil {
		return nil, err
	}
	var address []byte
	ip := net.ParseIP(host)
	switch {
	case ip.To4() != nil:
		address = append([]byte{1}, ip.To4()...)
	case ip != nil:
		address = append([]byte{4}, ip.To16()...)
	case len(host) <= 255:
		address = append([]byte{3, byte(len(host))}, host...)
	default:
		return nil, errors.New("destination name exceeds 255 bytes")
	}
	return binary.BigEndian.AppendUint16(address, port), nil
}

func ReadAddress(reader io.Reader, kind byte) (string, error) {
	var size int
	switch kind {
	case 1:
		size = net.IPv4len
	case 4:
		size = net.IPv6len
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", err
		}
		size = int(length[0])
		if size == 0 {
			return "", errors.New("empty destination name")
		}
	default:
		return "", ErrAddressType
	}
	data := make([]byte, size+2)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", err
	}
	host := string(data[:size])
	if kind != 3 {
		host = net.IP(data[:size]).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(data[size:])))), nil
}
