package wire

import (
	"bufio"
	"io"
	"net"
	"sync"
)

type BufferedConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (conn *BufferedConn) Read(data []byte) (int, error) {
	return conn.Reader.Read(data)
}

func (conn *BufferedConn) CloseWrite() error {
	return CloseWrite(conn.Conn)
}

func CloseWrite(conn net.Conn) error {
	if writer, ok := conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return conn.Close()
}

var relayBuffers = sync.Pool{New: func() any { return new([32 * 1024]byte) }}

func copyRelay(destination io.Writer, source io.Reader) (int64, error) {
	// Preserve the connection's optimized copy methods when present.
	if _, ok := source.(io.WriterTo); ok {
		return io.Copy(destination, source)
	}
	if _, ok := destination.(io.ReaderFrom); ok {
		return io.Copy(destination, source)
	}
	// Stream wrappers used by the proxy fall back to a regular buffer.
	buffer := relayBuffers.Get().(*[32 * 1024]byte)
	defer relayBuffers.Put(buffer)
	return io.CopyBuffer(destination, source, buffer[:])
}

func Relay(client, upstream net.Conn) {
	results := make(chan error, 2)
	copyStream := func(destination, source net.Conn) {
		_, err := copyRelay(destination, source)
		if err == nil {
			err = CloseWrite(destination)
		}
		results <- err
	}
	go copyStream(upstream, client)
	go copyStream(client, upstream)
	if <-results != nil {
		client.Close()
		upstream.Close()
	}
	<-results
}
