package wire

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
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
	failure := transfer(relayFixture{}, source, "client", "upstream")
	if failure == nil || failure.Endpoint != "upstream" || failure.Operation != "read" ||
		!errors.Is(failure.Err, io.ErrNoProgress) || reads != 100 {
		t.Fatalf("no-progress stream returned %+v after %d reads", failure, reads)
	}
}

func TestRelayAttributesWriteErrorToDestination(t *testing.T) {
	origin := bytes.NewReader([]byte("reply"))
	source := relayFixture{read: origin.Read}
	destination := relayFixture{write: func([]byte) (int, error) { return 0, io.ErrClosedPipe }}
	failure := transfer(destination, source, "client", "upstream")
	if failure == nil || failure.Endpoint != "client" || failure.Operation != "write" ||
		!errors.Is(failure.Err, io.ErrClosedPipe) {
		t.Fatalf("write failure was not attributed to client: %+v", failure)
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
