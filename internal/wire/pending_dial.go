package wire

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

var ErrConnectionLimit = errors.New("proxy connection limit reached")

func DescriptorExhausted(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

// DialWithClient watches the ingress while opening a tunnel. It peeks into
// a bounded buffer so any early payload can still be relayed, and it stops
// reading before the established relay takes over.
func DialWithClient(ctx context.Context, client net.Conn, reader *bufio.Reader, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	dialFinished := make(chan struct{})
	go func() {
		defer close(done)
		for reader.Buffered() < reader.Size() {
			_, err := reader.Peek(reader.Buffered() + 1)
			if err == nil {
				continue
			}
			var timeout net.Error
			switch {
			case errors.As(err, &timeout) && timeout.Timeout():
				// The dial completed and interrupted the pending read.
			case errors.Is(err, io.EOF) && reader.Buffered() > 0:
				// The client sent a request and half-closed early.
			default:
				cancel()
			}
			return
		}
		if tcp := pollableTCP(client); tcp != nil {
			// The read-ahead buffer must stay bounded and its payload
			// cannot be discarded. Check for a reset without reading it.
			ticker := time.NewTicker(tcpFailureInterval)
			defer ticker.Stop()
			for {
				select {
				case <-dialFinished:
					return
				case <-ctx.Done():
					return
				case <-ticker.C:
					if pendingTCPError(tcp) != nil {
						cancel()
						return
					}
				}
			}
		}
	}()
	conn, err := dial(ctx)
	close(dialFinished)
	interruptErr := client.SetReadDeadline(time.Now())
	if interruptErr != nil {
		_ = client.Close()
	}
	<-done
	resetErr := client.SetReadDeadline(time.Time{})
	if err == nil {
		err = errors.Join(ctx.Err(), interruptErr, resetErr)
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	return conn, nil
}
