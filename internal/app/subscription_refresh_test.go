package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/profile"
	"mac-proxy/internal/sysproxy"
)

func cachedSubscription(t *testing.T, source string, subs []engine.Subscription) (*Supervisor, string, engine.Config, []byte) {
	t.Helper()
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	cfg := engine.Default()
	cfg.Subscriptions = subs
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range subs {
		if err := profile.SaveSnapshot(cache, sub, &profile.Snapshot{
			Updated: time.Now().UnixMilli(), Nodes: []outbound.Node{{Name: source + sub.Name, Type: "socks5", Server: "127.0.0.1:19005"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Open(path, cache, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Start(sysproxy.Target{}); err != nil {
		t.Fatal(err)
	}
	return s, cache, cfg, raw
}

func TestSubscriptionRefreshUsesConfiguredDefaultAndPerSourceOverride(t *testing.T) {
	var requested atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/default" {
			t.Error("refreshed a source before its longer override elapsed")
		}
		requested.Add(1)
		io.WriteString(w, "ss://aes-128-gcm:a@127.0.0.1:19001#Fresh")
	}))
	defer server.Close()
	a := engine.Subscription{Name: "default", URL: server.URL + "/default"}
	b := engine.Subscription{Name: "override", URL: server.URL + "/override", Interval: 3600}
	s, _, cfg, _ := cachedSubscription(t, "cached-", []engine.Subscription{a, b})
	cfg.SubscriptionRefreshMin = 10
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.WriteAtomic(s.path, data); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for _, sub := range cfg.Subscriptions {
		meta := s.subMeta[sub.URL]
		meta.Checked = time.Now().Add(-20 * time.Minute).UnixMilli()
		s.subMeta[sub.URL] = meta
	}
	s.mu.Unlock()
	s.RefreshSubscriptions(context.Background(), false)
	if requested.Load() != 1 {
		t.Fatalf("scheduled %d requests, want 1", requested.Load())
	}
}

func TestSubscriptionRefreshSharesConnectionAndPreservesUnchangedEngine(t *testing.T) {
	var phase atomic.Int32
	var requestsA atomic.Int32
	var mu sync.Mutex
	var initialAddresses []string
	const modified = "Mon, 01 Jan 2024 12:00:00 GMT"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := phase.Load()
		if state == 0 {
			mu.Lock()
			initialAddresses = append(initialAddresses, r.RemoteAddr)
			mu.Unlock()
		}
		w.Header().Set("ETag", `"initial"`)
		w.Header().Set("Last-Modified", modified)
		w.Header().Set("Subscription-Userinfo", "upload=2; download=3; total=10")
		if r.URL.Path == "/a" {
			requestsA.Add(1)
			switch state {
			case 1:
				if r.Header.Get("If-None-Match") != `"initial"` || r.Header.Get("If-Modified-Since") != modified {
					t.Error("refresh did not send validators from the cached response")
				}
				w.Header().Set("Subscription-Userinfo", "upload=30; download=40; total=10")
				w.WriteHeader(http.StatusNotModified)
				return
			case 2:
				w.Header().Set("Retry-After", "90")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			io.WriteString(w, "ss://aes-128-gcm:a@127.0.0.1:19001#Alpha")
			return
		}
		if state == 2 {
			io.WriteString(w, "ss://aes-128-gcm:b@127.0.0.1:19002#Beta2")
			return
		}
		if state == 1 {
			w.Header().Set("Subscription-Userinfo", "upload=3; download=4; total=10")
		}
		io.WriteString(w, "ss://aes-128-gcm:b@127.0.0.1:19002#Beta")
	}))
	defer server.Close()
	a := engine.Subscription{Name: "a", URL: server.URL + "/a"}
	b := engine.Subscription{Name: "b", URL: server.URL + "/b"}
	s, cache, cfg, configBytes := cachedSubscription(t, "cached-", []engine.Subscription{a, b})
	s.RefreshSubscriptions(context.Background(), true)
	mu.Lock()
	if len(initialAddresses) != 2 || initialAddresses[0] != initialAddresses[1] {
		t.Fatalf("same origin used separate sockets: %v", initialAddresses)
	}
	mu.Unlock()
	first := s.Engine()
	status := s.Status()
	before, err := profile.LoadSnapshot(cache, a)
	if err != nil || before.Validators == nil || before.Usage == nil {
		t.Fatalf("initial conditional snapshot: %+v, %v", before, err)
	}
	time.Sleep(5 * time.Millisecond)
	phase.Store(1)
	s.RefreshSubscriptions(context.Background(), true)
	if s.Engine() != first || s.Status().Reloaded != status.Reloaded {
		t.Fatal("304 and unchanged 200 responses rebuilt the engine")
	}
	after, err := profile.LoadSnapshot(cache, a)
	if err != nil || !reflect.DeepEqual(after.Nodes, before.Nodes) || !reflect.DeepEqual(after.Usage, before.Usage) ||
		!reflect.DeepEqual(after.Samples, before.Samples) || after.Updated != before.Updated || after.CheckedAt() <= before.CheckedAt() {
		t.Fatalf("304 changed content or missed check metadata: %+v, %v", after, err)
	}
	if actual := s.Status().Subscriptions; actual[0].Checked <= actual[0].Updated ||
		actual[0].Error != "" || actual[1].Usage == nil || actual[1].Usage.Used == nil || *actual[1].Usage.Used != 7 {
		t.Fatalf("runtime check or quota state not updated: %+v", actual)
	}
	s.RefreshSubscriptions(context.Background(), false)
	if got := requestsA.Load(); got != 2 {
		t.Fatalf("304 freshness did not prevent another scheduled request: %d", got)
	}
	aBytes, _ := os.ReadFile(profile.SnapshotPath(cache, a))
	phase.Store(2)
	s.RefreshSubscriptions(context.Background(), true)
	if s.Engine() == first {
		t.Fatal("successful source did not apply beside a failed source")
	}
	var alpha, beta bool
	for _, node := range s.Status().Nodes {
		alpha = alpha || node.Name == "Alpha"
		beta = beta || node.Name == "Beta2"
	}
	if !alpha || !beta {
		t.Fatalf("split refresh lost good nodes: %+v", s.Status().Nodes)
	}
	var burst sync.WaitGroup
	for range 20 {
		burst.Go(func() { s.RefreshSubscription(context.Background(), a.Key()) })
	}
	burst.Wait()
	if _, err := profile.RefreshSnapshot(context.Background(), cfg, a, "", cache, backend.Native{}, nil); err == nil {
		t.Fatal("offline refresh did not observe the saved Retry-After")
	}
	kept, _ := os.ReadFile(profile.SnapshotPath(cache, a))
	if requestsA.Load() != 3 || !bytes.Equal(kept, aBytes) || s.Status().Subscriptions[0].Error == "" {
		t.Fatal("rate limit produced more requests, changed the snapshot, or lacked a status")
	}
	path := filepath.Join(filepath.Dir(cache), "config.json")
	userFile, _ := os.ReadFile(path)
	if !bytes.Equal(userFile, configBytes) {
		t.Fatal("refresh rewrote the user's configuration")
	}
}

func TestSubscriptionRefreshReadOnlyCacheKeepsTraffic(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires normal filesystem permissions")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ss://aes-128-gcm:a@127.0.0.1:19001#Replacement")
	}))
	defer server.Close()
	sub := engine.Subscription{Name: "original", URL: server.URL}
	s, cache, _, _ := cachedSubscription(t, "", []engine.Subscription{sub})
	path := profile.SnapshotPath(cache, sub)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	old := s.Engine()
	s.RefreshSubscription(context.Background(), sub.Key())
	actual := s.Status().Subscriptions[0]
	if s.Engine() != old || actual.Error == "" || !strings.Contains(strings.ToLower(actual.Error), "permission") {
		t.Fatalf("read-only cache was not diagnosed: %+v", actual)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("unwritable cache changed: %v", err)
	}
	conn, err := s.Dial(context.Background(), "test", echo(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	conn.Write([]byte("alive"))
	var reply [5]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "alive" {
		t.Fatalf("existing routing stopped after cache failure: %q %v", reply[:], err)
	}
}
