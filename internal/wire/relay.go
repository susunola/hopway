package wire

import (
	"bufio"
	"errors"
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

type RelayError struct {
	Endpoint  string
	Operation string
	Err       error
}

type relayReader struct {
	io.Reader
	emptyReads int
}

func (r *relayReader) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	if n == 0 && err == nil {
		r.emptyReads++
		if r.emptyReads >= 100 {
			err = io.ErrNoProgress
		}
	} else {
		r.emptyReads = 0
	}
	return n, err
}

type relayWriter struct {
	io.Writer
	err error
}

func (w *relayWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

func transfer(destination, source net.Conn, to, from string) *RelayError {
	_, directSource := source.(*net.TCPConn)
	_, directDestination := destination.(*net.TCPConn)
	if directSource && directDestination {
		// Preserve native TCP copy optimizations when neither side is
		// wrapped. Socket errors identify the operation themselves.
		if _, err := copyRelay(destination, source); err != nil {
			var op *net.OpError
			if errors.As(err, &op) {
				switch op.Op {
				case "read":
					return &RelayError{from, "read", err}
				case "write":
					return &RelayError{to, "write", err}
				}
			}
			return &RelayError{from, "transfer", err}
		}
	} else {
		reader, writer := relayReader{Reader: source}, relayWriter{Writer: destination}
		if _, err := copyRelay(&writer, &reader); err != nil {
			if writer.err != nil {
				return &RelayError{to, "write", err}
			}
			return &RelayError{from, "read", err}
		}
	}
	if err := CloseWrite(destination); err != nil {
		return &RelayError{to, "write", err}
	}
	return nil
}

func Relay(client, upstream net.Conn) {
	results := make(chan *RelayError, 2)
	go func() { results <- transfer(upstream, client, "upstream", "client") }()
	go func() { results <- transfer(client, upstream, "client", "upstream") }()
	first := <-results
	if first != nil {
		reportRelayFailure(upstream, first)
		client.Close()
		upstream.Close()
	}
	if second := <-results; first == nil && second != nil {
		reportRelayFailure(upstream, second)
		client.Close()
		upstream.Close()
	}
}

func reportRelayFailure(upstream net.Conn, failure *RelayError) {
	if reporter, ok := upstream.(interface{ RecordRelayError(*RelayError) }); ok {
		reporter.RecordRelayError(failure)
	}
}
