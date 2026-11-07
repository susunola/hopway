package importer

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/wire"
)

const downloadNode = "ss://aes-128-gcm:a@127.0.0.1:19001#Fixture\n"

func TestSameNameWithDifferentCredentialsCanConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "socks5://a:x@%s#Same\nsocks5://b:y@%s#Same\n", listener.Addr(), listener.Addr())
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := Import(ctx, strings.NewReader(server.URL), engine.Default(), backend.Native{})
	if err != nil || result.Added != 2 || result.Config.Nodes[0].Name == result.Config.Nodes[1].Name {
		t.Fatalf("expected distinct names and both credentials: added %d, %v", result.Added, err)
	}
	go func() {
		for _, expected := range []string{"\x01\x01a\x01x", "\x01\x01b\x01y"} {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				var greeting [3]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [3]byte{5, 1, 2} {
					return
				}
				conn.Write([]byte{5, 2})
				var auth [5]byte
				if _, err := io.ReadFull(conn, auth[:]); err != nil || string(auth[:]) != expected {
					return
				}
				conn.Write([]byte{1, 0})
				var header [4]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					return
				}
				if _, err := wire.ReadAddress(conn, header[3]); err != nil {
					return
				}
				conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0, expected[2]})
			}()
		}
	}()
	core, err := engine.New(result.Config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	for i, node := range result.Config.Nodes {
		if err := core.SetPolicy(engine.Policy{Mode: "global", Selected: node.Name}); err != nil {
			t.Fatal(err)
		}
		conn, err := core.Dial(ctx, "fixture", "example.test:443")
		if err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		var received [1]byte
		_, err = io.ReadFull(conn, received[:])
		conn.Close()
		if err != nil || received[0] != byte('a'+i) {
			t.Fatalf("node %d did not use its own credentials: %v", i, err)
		}
	}
}

func gzipFixture(t *testing.T, input []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func TestCompressedSubscriptionLimitAndTruncation(t *testing.T) {
	valid := gzipFixture(t, []byte(downloadNode))
	large := gzipFixture(t, bytes.Repeat([]byte{'x'}, MaxSize+1))
	if len(large) > 4<<10 {
		t.Fatalf("oversize fixture should be compact on the wire: %d", len(large))
	}
	for _, sample := range []struct {
		name string
		wire []byte
		want string
	}{
		{"valid", valid, ""},
		{"expansion", large, "超过 1 MB"},
		{"truncated trailer", valid[:len(valid)-5], "不完整或损坏"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept-Encoding") != "gzip" {
					t.Error("client did not negotiate the supported compression")
				}
				w.Header().Set("Content-Encoding", "gzip")
				w.Write(sample.wire)
			}))
			defer server.Close()
			result, err := Import(context.Background(), strings.NewReader(server.URL), engine.Default(), backend.Native{})
			if sample.want == "" {
				if err != nil || result.Added != 1 {
					t.Fatalf("valid gzip: added %d, error %v", result.Added, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), sample.want) || result.Added != 0 {
				t.Fatalf("invalid gzip produced nodes or the wrong error: added %d, error %v", result.Added, err)
			}
		})
	}
}

func TestSubscriptionRetryBackoffAndCredentialStop(t *testing.T) {
	for _, sample := range []struct {
		status, attempts int
	}{
		{http.StatusServiceUnavailable, 2},
		{http.StatusUnauthorized, 1},
		{http.StatusForbidden, 1},
	} {
		t.Run(http.StatusText(sample.status), func(t *testing.T) {
			var count atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if count.Add(1) == 1 {
					if sample.attempts == 1 {
						w.Header().Set("Retry-After", "60")
					}
					w.WriteHeader(sample.status)
					return
				}
				io.WriteString(w, downloadNode)
			}))
			defer server.Close()
			start := time.Now()
			result, err := Import(context.Background(), strings.NewReader(server.URL), engine.Default(), backend.Native{})
			if int(count.Load()) != sample.attempts {
				t.Fatalf("requests = %d, want %d", count.Load(), sample.attempts)
			}
			if sample.attempts == 2 {
				if err != nil || result.Added != 1 || time.Since(start) < 180*time.Millisecond {
					t.Fatalf("transient response was not retried with backoff: %v", err)
				}
			} else {
				var download *DownloadError
				if !errors.As(err, &download) || download.Status != sample.status || !download.RetryAfter.IsZero() {
					t.Fatalf("expected a credential failure: %v", err)
				}
			}
		})
	}
}

func TestSubscriptionValidatorFollowsOnlyMatchingResource(t *testing.T) {
	var requests atomic.Int32
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"validator"`)
		if requests.Add(1) == 2 {
			if r.Header.Get("If-None-Match") != `"validator"` {
				t.Error("missing validator at original final endpoint")
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			t.Error("validator leaked to an unrelated resource")
		}
		io.WriteString(w, downloadNode)
	}))
	defer final.Close()
	var target atomic.Value
	target.Store(final.URL + "/one")
	entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			t.Error("validator leaked to the redirect entry point")
		}
		http.Redirect(w, r, target.Load().(string), http.StatusFound)
	}))
	defer entry.Close()
	fetch := func(options Options) (Result, error) {
		return ImportWith(context.Background(), strings.NewReader(entry.URL), engine.Default(), backend.Native{}, options)
	}
	first, err := fetch(Options{})
	if err != nil || first.Added != 1 {
		t.Fatalf("first import: %v", err)
	}
	again, err := fetch(Options{Validators: first.Validators})
	if err != nil || !again.NotModified {
		t.Fatalf("conditional refresh: %+v, %v", again, err)
	}
	target.Store(final.URL + "/two")
	again, err = fetch(Options{Validators: first.Validators})
	if err != nil || again.NotModified || again.Added != 1 {
		t.Fatalf("redirect changed resources: %+v, %v", again, err)
	}
}

func TestSubscriptionRedirectLoopAndUTF8(t *testing.T) {
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer loop.Close()
	base, impl := engine.Default(), backend.Native{}
	_, err := Import(context.Background(), strings.NewReader(loop.URL+"/loop"), base, impl)
	if !errors.Is(err, errInvalidRedirect) {
		t.Fatalf("redirect loop was not detected: %v", err)
	}
	result, err := Import(context.Background(), strings.NewReader("\ufeff"+downloadNode), base, impl)
	if err != nil || result.Added != 1 {
		t.Fatalf("UTF-8 BOM was not handled: %v", err)
	}
	_, err = Import(context.Background(), strings.NewReader(downloadNode+"\xff"), base, impl)
	if err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("bad encoding was not diagnosed: %v", err)
	}
}
