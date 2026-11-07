package profile

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
)

func TestConditionalRefreshCannotReplaceConcurrentImport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"first"`)
		if r.Header.Get("If-None-Match") == `"first"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		io.WriteString(w, "ss://aes-128-gcm:a@127.0.0.1:19001#First")
	}))
	defer server.Close()
	sub := engine.Subscription{Name: "fixture", URL: server.URL}
	cfg, dir, impl := engine.Default(), t.TempDir(), backend.Native{}
	cfg.Subscriptions = []engine.Subscription{sub}
	first, err := RefreshSnapshot(context.Background(), cfg, sub, dir, impl, nil)
	if err != nil {
		t.Fatal(err)
	}
	queued, err := FetchRefresh(context.Background(), sub, dir, impl, nil)
	if err != nil || !queued.notModified {
		t.Fatalf("conditional fixture: %+v, %v", queued, err)
	}
	replacement := &Snapshot{Updated: first.Updated + 100, Nodes: []outbound.Node{
		{Name: "Newer", Type: "socks5", Server: "127.0.0.1:19002"},
	}}
	if err := SaveSnapshot(dir, sub, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := CommitRefresh(cfg, sub, queued, dir, impl); err == nil {
		t.Fatal("late 304 accepted after a concurrent import")
	}
	after, err := LoadSnapshot(dir, sub)
	if err != nil || len(after.Nodes) != 1 || after.Nodes[0].Name != "Newer" || after.Updated != replacement.Updated {
		t.Fatalf("late refresh replaced current snapshot: %+v, %v", after, err)
	}
}

func TestTruncatedCompressedRefreshKeepsSnapshot(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	io.WriteString(writer, "ss://aes-128-gcm:b@127.0.0.1:19001#Uncommitted")
	writer.Close()
	payload := compressed.Bytes()[:compressed.Len()-5]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(payload)
	}))
	defer server.Close()
	sub := engine.Subscription{Name: "fixture", URL: server.URL}
	cfg, dir := engine.Default(), t.TempDir()
	cfg.Subscriptions = []engine.Subscription{sub}
	original := &Snapshot{Updated: time.Now().UnixMilli(), Nodes: []outbound.Node{
		{Name: "Original", Type: "socks5", Server: "127.0.0.1:19002"},
	}}
	if err := SaveSnapshot(dir, sub, original); err != nil {
		t.Fatal(err)
	}
	path := SnapshotPath(dir, sub)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = RefreshSnapshot(context.Background(), cfg, sub, dir, backend.Native{}, nil)
	if err == nil || !strings.Contains(err.Error(), "不完整或损坏") {
		t.Fatalf("truncated response was not diagnosed: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("truncated response replaced last good snapshot: %v", err)
	}
}
