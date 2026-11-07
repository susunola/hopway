package tun

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"mac-proxy/internal/peer"
	"mac-proxy/internal/wire"
)

const sniffWait = 300 * time.Millisecond

// sniff peeks at the first bytes the application sends and extracts the
// server name from a TLS ClientHello or an HTTP Host header. The returned
// connection replays the peeked bytes. Protocols where the server speaks
// first simply time out after sniffWait and keep going unsniffed.
func sniff(conn net.Conn) (string, peer.TargetSource, *wire.BufferedConn) {
	reader := bufio.NewReaderSize(conn, 16<<10)
	replay := &wire.BufferedConn{Conn: conn, Reader: reader}
	conn.SetReadDeadline(time.Now().Add(sniffWait))
	defer conn.SetReadDeadline(time.Time{})
	head, err := reader.Peek(5)
	if err != nil {
		return "", peer.TargetIP, replay
	}
	if head[0] == 0x16 && head[1] == 3 { // TLS handshake record
		length := int(binary.BigEndian.Uint16(head[3:5]))
		record, err := reader.Peek(5 + min(length, reader.Size()-5))
		if err != nil && len(record) < 5 {
			return "", peer.TargetIP, replay
		}
		if name := serverName(record[5:]); name != "" {
			return name, peer.TargetTLSSNI, replay
		}
		return "", peer.TargetIP, replay
	}
	if isHTTPMethod(head) {
		for size := 512; size <= reader.Size(); size *= 2 {
			data, _ := reader.Peek(min(size, reader.Buffered()+reader.Size()))
			if host := httpHost(data); host != "" {
				return host, peer.TargetHTTPHost, replay
			}
			if bytes.Contains(data, []byte("\r\n\r\n")) || len(data) < size {
				break
			}
		}
	}
	return "", peer.TargetIP, replay
}

func isHTTPMethod(head []byte) bool {
	for _, method := range []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC", "CONN"} {
		if bytes.HasPrefix(head, []byte(method)) {
			return true
		}
	}
	return false
}

func httpHost(data []byte) string {
	for _, line := range strings.Split(string(data), "\r\n")[1:] {
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			host := strings.TrimSpace(value)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			return strings.ToLower(strings.Trim(host, "[]"))
		}
	}
	return ""
}

// serverName parses the SNI extension out of a ClientHello handshake message.
func serverName(hello []byte) string {
	// handshake type(1) length(3) version(2) random(32)
	if len(hello) < 38 || hello[0] != 1 {
		return ""
	}
	p := hello[38:]
	skip := func(lengthBytes int) bool {
		if len(p) < lengthBytes {
			return false
		}
		n := 0
		for i := 0; i < lengthBytes; i++ {
			n = n<<8 | int(p[i])
		}
		if len(p) < lengthBytes+n {
			return false
		}
		p = p[lengthBytes+n:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return ""
	}
	if len(p) < 2 {
		return ""
	}
	p = p[2:min(len(p), 2+int(binary.BigEndian.Uint16(p)))]
	for len(p) >= 4 {
		kind, size := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		if len(p) < 4+size {
			return ""
		}
		data := p[4 : 4+size]
		p = p[4+size:]
		if kind != 0 || len(data) < 5 { // server_name
			continue
		}
		list := data[2:]
		for len(list) >= 3 {
			nameType, nameLength := list[0], int(binary.BigEndian.Uint16(list[1:]))
			if len(list) < 3+nameLength {
				return ""
			}
			if nameType == 0 {
				return strings.ToLower(string(list[3 : 3+nameLength]))
			}
			list = list[3+nameLength:]
		}
	}
	return ""
}
