package wire

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
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

const (
	relayBufferSize     = 32 * 1024
	relayBufferCacheCap = 128 // at most 4 MiB of idle relay buffers
)

var relayBuffers = make(chan *[relayBufferSize]byte, relayBufferCacheCap)

func copyRelay(destination io.Writer, source io.Reader) (int64, error) {
	// Preserve the connection's optimized copy methods when present.
	if _, ok := source.(io.WriterTo); ok {
		return io.Copy(destination, source)
	}
	if _, ok := destination.(io.ReaderFrom); ok {
		return io.Copy(destination, source)
	}
	// Stream wrappers used by the proxy fall back to a regular buffer.
	var buffer *[relayBufferSize]byte
	select {
	case buffer = <-relayBuffers:
	default:
		buffer = new([relayBufferSize]byte)
	}
	defer func() {
		select {
		case relayBuffers <- buffer:
		default: // Let surplus buffers become collectible after a burst.
		}
	}()
	return io.CopyBuffer(destination, source, buffer[:])
}

type RelayError struct {
	Endpoint  string
	Operation string
	Err       error
}

var ErrRelayIdle = errors.New("tunnel closed after its configured idle interval")

// Relay activity is timestamped only after payload makes forward progress.
// The relay's coordinator owns the timer, including every reset and stop.
type relayActivity struct {
	start time.Time
	last  atomic.Int64
}

func (a *relayActivity) touch() {
	now := time.Since(a.start).Nanoseconds()
	for previous := a.last.Load(); previous >= 0 && now > previous; previous = a.last.Load() {
		if a.last.CompareAndSwap(previous, now) {
			return
		}
	}
}

func (a *relayActivity) remaining(idle time.Duration) time.Duration {
	for {
		previous := a.last.Load()
		remaining := idle - (time.Since(a.start) - time.Duration(previous))
		if remaining > 0 {
			return remaining
		}
		if a.last.CompareAndSwap(previous, -1) {
			return 0
		}
	}
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
	err      error
	activity *relayActivity
}

func (w *relayWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	if w.activity != nil && n > 0 {
		w.activity.touch()
	}
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

func transfer(destination, source net.Conn, to, from string, activity *relayActivity) *RelayError {
	_, directSource := source.(*net.TCPConn)
	_, directDestination := destination.(*net.TCPConn)
	if directSource && directDestination && activity == nil {
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
		reader, writer := relayReader{Reader: source}, relayWriter{Writer: destination, activity: activity}
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
	var activity *relayActivity
	var timer *time.Timer
	var expiry <-chan time.Time
	var idle time.Duration
	if config, ok := upstream.(interface{ RelayIdleTimeout() time.Duration }); ok {
		idle = config.RelayIdleTimeout()
		if idle > 0 {
			activity = &relayActivity{start: time.Now()}
			timer = time.NewTimer(idle)
			defer timer.Stop()
			expiry = timer.C
		}
	}
	results := make(chan *RelayError, 2)
	go func() { results <- transfer(upstream, client, "upstream", "client", activity) }()
	go func() { results <- transfer(client, upstream, "client", "upstream", activity) }()
	var stopped bool
	for finished := 0; finished < 2; {
		var failure *RelayError
		select {
		case failure = <-results:
			finished++
		case <-expiry:
			if remaining := activity.remaining(idle); remaining > 0 {
				timer.Reset(remaining)
				continue
			}
			failure = &RelayError{Operation: "idle", Err: ErrRelayIdle}
		}
		if failure != nil && !stopped {
			stopped = true
			expiry = nil
			reportRelayFailure(upstream, failure)
			client.Close()
			upstream.Close()
		}
	}
}

func reportRelayFailure(upstream net.Conn, failure *RelayError) {
	if reporter, ok := upstream.(interface{ RecordRelayError(*RelayError) }); ok {
		reporter.RecordRelayError(failure)
	}
}
