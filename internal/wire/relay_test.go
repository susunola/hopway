package wire

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type relayFixture struct {
	net.Conn
	read  func([]byte) (int, error)
	write func([]byte) (int, error)
}

func (c relayFixture) Read(b []byte) (int, error)  { return c.read(b) }
func (c relayFixture) Write(b []byte) (int, error) { return c.write(b) }

func TestRelayTerminatesAStreamThatNeverMakesProgress(t *testing.T) {
	var reads int
	source := relayFixture{read: func([]byte) (int, error) {
		reads++
		return 0, nil
	}}
	failure := transfer(relayFixture{}, source, "client", "upstream", nil, nil)
	if failure == nil || failure.Endpoint != "upstream" || failure.Operation != "read" ||
		!errors.Is(failure.Err, io.ErrNoProgress) || reads != 100 {
		t.Fatalf("no-progress stream returned %+v after %d reads", failure, reads)
	}
}

func TestRelayAttributesWriteErrorToDestination(t *testing.T) {
	origin := bytes.NewReader([]byte("reply"))
	source := relayFixture{read: origin.Read}
	destination := relayFixture{write: func([]byte) (int, error) { return 0, io.ErrClosedPipe }}
	failure := transfer(destination, source, "client", "upstream", nil, nil)
	if failure == nil || failure.Endpoint != "client" || failure.Operation != "write" ||
		!errors.Is(failure.Err, io.ErrClosedPipe) {
		t.Fatalf("write failure was not attributed to client: %+v", failure)
	}
}

func TestRelayBufferCacheBoundsAReleasedBurst(t *testing.T) {
	const streams = relayBufferCacheCap + 32
	var copies sync.WaitGroup
	started := make(chan struct{}, streams)
	release := make(chan struct{})
	for i := range streams {
		copies.Go(func() {
			payload := []byte{byte(i), byte(i ^ 0xff)}
			read := false
			source := relayFixture{read: func(buffer []byte) (int, error) {
				if read {
					return 0, io.EOF
				}
				read = true
				copy(buffer, payload)
				started <- struct{}{}
				<-release
				return len(payload), nil
			}}
			var received bytes.Buffer
			n, err := copyRelay(struct{ io.Writer }{&received}, source)
			if err != nil || n != int64(len(payload)) || !bytes.Equal(received.Bytes(), payload) {
				t.Errorf("copy %d: received %x (%d bytes), %v", i, received.Bytes(), n, err)
			}
		})
	}
	for range streams {
		<-started
	}
	close(release)
	copies.Wait()
	if count := len(relayBuffers); count != relayBufferCacheCap {
		t.Fatalf("retained %d idle buffers, expected %d", count, relayBufferCacheCap)
	}
}

type idleRelayFixture struct {
	net.Conn
	timeout time.Duration
	failure chan *RelayError
}

func (f idleRelayFixture) RelayIdleTimeout() time.Duration  { return f.timeout }
func (f idleRelayFixture) RecordRelayError(err *RelayError) { f.failure <- err }

func TestRelayIdleTimeoutFollowsOneWayProgress(t *testing.T) {
	client, ingress := net.Pipe()
	upstream, target := net.Pipe()
	defer client.Close()
	defer ingress.Close()
	defer upstream.Close()
	defer target.Close()
	deadline := time.Now().Add(3 * time.Second)
	client.SetDeadline(deadline)
	target.SetDeadline(deadline)

	failure := make(chan *RelayError, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Relay(ingress, idleRelayFixture{upstream, 400 * time.Millisecond, failure})
	}()
	for i := range 6 {
		time.Sleep(90 * time.Millisecond)
		if _, err := target.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("one-way keepalive stopped at %d: %v", i, err)
		}
		var received [1]byte
		if _, err := io.ReadFull(client, received[:]); err != nil || received[0] != byte(i) {
			t.Fatalf("one-way keepalive %d: received %x, error %v", i, received, err)
		}
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close both streams after inactivity")
	}
	select {
	case err := <-failure:
		if !errors.Is(err.Err, ErrRelayIdle) {
			t.Fatalf("unexpected reason for idle close: %v", err)
		}
	default:
		t.Fatal("relay did not report an idle close")
	}
}

// The interfaces deliberately hide WriterTo and ReaderFrom, as happens for
// wrapped connections. Compare the two paths with identical payloads.
func BenchmarkRelayWrappedCopy(b *testing.B) {
	payload := make([]byte, 64*1024)
	for _, test := range []struct {
		name string
		copy func(io.Writer, io.Reader) (int64, error)
	}{
		{"standard", io.Copy},
		{"pooled", copyRelay},
	} {
		b.Run(test.name, func(b *testing.B) {
			source := bytes.NewReader(payload)
			reader := struct{ io.Reader }{source}
			writer := struct{ io.Writer }{io.Discard}
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				source.Reset(payload)
				if n, err := test.copy(writer, reader); err != nil || n != int64(len(payload)) {
					b.Fatalf("copy: %d bytes, %v", n, err)
				}
			}
		})
	}
}
