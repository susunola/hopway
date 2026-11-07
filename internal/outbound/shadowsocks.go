package outbound

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"mac-proxy/internal/wire"
)

const maxChunk = 0x3fff

func cipherSize(name string) int {
	switch name {
	case "aes-128-gcm":
		return 16
	case "aes-256-gcm":
		return 32
	default:
		return 0
	}
}

func passwordKey(password string, size int) []byte {
	// The legacy AEAD protocol specifies OpenSSL EVP_BytesToKey with MD5.
	first := md5.Sum([]byte(password))
	key := first[:]
	if size > len(first) {
		second := md5.Sum(append(first[:len(first):len(first)], password...))
		key = append(key, second[:]...)
	}
	return key[:size]
}

type aeadStream struct {
	aead  cipher.AEAD
	nonce [12]byte
}

func newStream(key, salt []byte) (aeadStream, error) {
	subkey, err := hkdf.Key(sha1.New, key, salt, "ss-subkey", len(key))
	if err != nil {
		return aeadStream{}, err
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return aeadStream{}, err
	}
	aead, err := cipher.NewGCM(block)
	return aeadStream{aead: aead}, err
}

func (stream *aeadStream) increment() {
	for index := range stream.nonce {
		stream.nonce[index]++
		if stream.nonce[index] != 0 {
			return
		}
	}
}

func (stream *aeadStream) seal(dst, payload []byte) []byte {
	dst = stream.aead.Seal(dst, stream.nonce[:], payload, nil)
	stream.increment()
	return dst
}

func (stream *aeadStream) read(reader io.Reader, size int) ([]byte, error) {
	data := make([]byte, size+stream.aead.Overhead())
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, err
	}
	plain, err := stream.aead.Open(data[:0], stream.nonce[:], data, nil)
	stream.increment()
	return plain, err
}

// One goroutine reads and one writes. Each direction has independent state.
type shadowsocksConn struct {
	net.Conn
	key     []byte
	send    aeadStream
	receive aeadStream
	pending []byte
}

func (node Node) shadowsocksConnect(conn net.Conn, target string) (net.Conn, error) {
	address, err := wire.EncodeAddress(target)
	if err != nil {
		return nil, err
	}
	key := passwordKey(node.Password, cipherSize(node.Cipher))
	salt := make([]byte, len(key))
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	send, err := newStream(key, salt)
	if err != nil {
		return nil, err
	}
	stream := &shadowsocksConn{Conn: conn, key: key, send: send}
	if _, err := conn.Write(stream.frame(salt, address)); err != nil {
		return nil, err
	}
	return stream, nil
}

func (conn *shadowsocksConn) frame(prefix, data []byte) []byte {
	length := binary.BigEndian.AppendUint16(nil, uint16(len(data)))
	return conn.send.seal(conn.send.seal(prefix, length), data)
}

func (conn *shadowsocksConn) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if conn.receive.aead == nil {
		salt := make([]byte, len(conn.key))
		if _, err := io.ReadFull(conn.Conn, salt); err != nil {
			return 0, err
		}
		var err error
		conn.receive, err = newStream(conn.key, salt)
		if err != nil {
			return 0, err
		}
	}
	if len(conn.pending) == 0 {
		length, err := conn.receive.read(conn.Conn, 2)
		if err != nil {
			return 0, err
		}
		size := int(binary.BigEndian.Uint16(length))
		if size == 0 || size > maxChunk {
			return 0, errors.New("invalid Shadowsocks chunk length")
		}
		conn.pending, err = conn.receive.read(conn.Conn, size)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
	}
	count := copy(data, conn.pending)
	conn.pending = conn.pending[count:]
	return count, nil
}

func (conn *shadowsocksConn) Write(data []byte) (int, error) {
	written := 0
	for len(data) > 0 {
		size := min(len(data), maxChunk)
		if _, err := conn.Conn.Write(conn.frame(nil, data[:size])); err != nil {
			return written, err
		}
		written += size
		data = data[size:]
	}
	return written, nil
}

func (conn *shadowsocksConn) CloseWrite() error {
	return wire.CloseWrite(conn.Conn)
}
