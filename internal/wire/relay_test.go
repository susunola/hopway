package wire

import (
	"bytes"
	"io"
	"testing"
)

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
