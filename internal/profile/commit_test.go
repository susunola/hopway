package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
)

func TestConcurrentConfigurationWritersUseRevision(t *testing.T) {
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	ctx := context.Background()
	start := make(chan struct{})
	results := make(chan error, 12)
	for i := range cap(results) {
		go func() {
			<-start
			config := engine.Default()
			config.SOCKSPort = 18000 + i
			data, _ := json.Marshal(config)
			_, err := CommitConfig(ctx, path, cache, MissingRevision, data, backend.Native{})
			results <- err
		}()
	}
	close(start)
	wins := 0
	for range cap(results) {
		if err := <-results; err == nil {
			wins++
		} else if !errors.Is(err, ErrConfigurationChanged) {
			t.Fatal(err)
		}
	}
	doc, err := ReadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	config, err := doc.Config()
	if err != nil || wins != 1 || config.SOCKSPort < 18000 || config.SOCKSPort > 18011 {
		t.Fatalf("profile writer outcomes: %d successful, port %d, %v", wins, config.SOCKSPort, err)
	}
	if _, err := CommitConfig(ctx, path, cache, doc.Revision, []byte(`{"socksPort":70000}`), backend.Native{}); err == nil {
		t.Fatal("accepted an invalid candidate")
	}
	if after, err := ReadDocument(path); err != nil || !bytes.Equal(after.Bytes, doc.Bytes) {
		t.Fatalf("failed validation changed the committed document: %v", err)
	}
}

func TestConfigurationAndRefreshKeepIndependentChanges(t *testing.T) {
	refreshStarted, importStarted := make(chan struct{}), make(chan struct{})
	allowRefresh, allowImport := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/refresh":
			close(refreshStarted)
			select {
			case <-allowRefresh:
			case <-r.Context().Done():
				return
			}
			io.WriteString(w, "ss://aes-128-gcm:b@127.0.0.1:19002#Refreshed")
		case "/import":
			close(importStarted)
			select {
			case <-allowImport:
			case <-r.Context().Done():
				return
			}
			io.WriteString(w, "ss://aes-128-gcm:c@127.0.0.1:19003#Imported")
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	impl := backend.Native{}
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	config := engine.Default()
	sub := engine.Subscription{Name: "source", URL: server.URL + "/refresh"}
	config.Subscriptions = []engine.Subscription{sub}
	data, _ := json.Marshal(config)
	original, err := CommitConfig(ctx, path, cache, MissingRevision, data, impl)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSnapshot(cache, sub, &Snapshot{Updated: time.Now().UnixMilli(), Nodes: []outbound.Node{
		{Name: "Previous", Type: "socks5", Server: "127.0.0.1:19001"},
	}}); err != nil {
		t.Fatal(err)
	}
	refreshed, imported := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := RefreshSnapshot(ctx, config, sub, path, cache, impl, nil)
		refreshed <- err
	}()
	go func() {
		_, err := CommitImport(ctx, path, cache, original, server.URL+"/import", impl)
		imported <- err
	}()
	for _, ready := range []chan struct{}{refreshStarted, importStarted} {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("a concurrent HTTP download did not start")
		}
	}
	edited := config
	edited.Subscriptions = []engine.Subscription{sub}
	edited.Subscriptions[0].Alias = "Manual alias"
	edited.MaxDialAttempts = 2
	editedBytes, _ := json.Marshal(edited)
	saved, err := CommitConfig(ctx, path, cache, original, editedBytes, impl)
	if err != nil {
		t.Fatal(err)
	}
	close(allowImport)
	close(allowRefresh)
	if err := <-imported; !errors.Is(err, ErrConfigurationChanged) {
		t.Fatalf("slow stale import overwrote a manual edit: %v", err)
	}
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	loaded, err := Check(path, cache, func(config engine.Config) error { return engine.Validate(config, impl) })
	if err != nil || loaded.Revision != saved || loaded.User.MaxDialAttempts != 2 || len(loaded.User.Subscriptions) != 1 ||
		loaded.User.Subscriptions[0].Alias != "Manual alias" || len(loaded.Merged.Nodes) != 1 || loaded.Merged.Nodes[0].Name != "Refreshed" {
		t.Fatalf("expected both the manual edit and refresh to apply: %+v, %v", loaded, err)
	}
	if paths, err := filepath.Glob(filepath.Join(cache, "subscriptions", "*.json")); err != nil || len(paths) != 1 {
		t.Fatalf("stale import published an extra snapshot: %v, %v", paths, err)
	}
}

func TestReimportPublishesNewSnapshotWithoutChangingPrevious(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ss://aes-128-gcm:b@127.0.0.1:19002#Current")
	}))
	defer server.Close()
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	config := engine.Default()
	sub := engine.Subscription{Name: "old", Alias: "Kept alias", URL: server.URL}
	config.Subscriptions = []engine.Subscription{sub}
	data, _ := json.Marshal(config)
	ctx, impl := context.Background(), backend.Native{}
	initial, err := CommitConfig(ctx, path, cache, MissingRevision, data, impl)
	if err != nil {
		t.Fatal(err)
	}
	old := &Snapshot{Updated: time.Now().UnixMilli(), Nodes: []outbound.Node{
		{Name: "Previous", Type: "socks5", Server: "127.0.0.1:19001"},
	}}
	if err := SaveSnapshot(cache, sub, old); err != nil {
		t.Fatal(err)
	}
	oldBytes, err := os.ReadFile(SnapshotPath(cache, sub))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := FetchRefresh(ctx, sub, cache, impl, nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := CommitImport(ctx, path, cache, initial, server.URL, impl)
	if err != nil || receipt.Added != 1 {
		t.Fatalf("reimport failed: %v", err)
	}
	committed, err := engine.Decode(strings.NewReader(receipt.Text))
	if err != nil || len(committed.Subscriptions) != 1 {
		t.Fatalf("invalid import receipt: %v", err)
	}
	current := committed.Subscriptions[0]
	if current.SnapshotKey == "" || current.Alias != sub.Alias || current.Key() != sub.Key() {
		t.Fatal("reimport did not preserve source identity or publish a new snapshot key")
	}
	if after, err := os.ReadFile(SnapshotPath(cache, sub)); err != nil || !bytes.Equal(after, oldBytes) {
		t.Fatalf("reimport changed the previous snapshot: %v", err)
	}
	if snapshot, err := LoadSnapshot(cache, current); err != nil || len(snapshot.Nodes) != 1 || snapshot.Nodes[0].Name != "Current" {
		t.Fatalf("new snapshot was not committed: %+v, %v", snapshot, err)
	}
	if _, err := CommitRefresh(ctx, config, sub, pending, path, cache, impl); !errors.Is(err, ErrRefreshSourceChanged) {
		t.Fatalf("late refresh accepted after the snapshot generation changed: %v", err)
	}
}

func TestPreparedImportCommitsExactlyWhatWasPreviewed(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) != 1 {
			w.Header().Set("ETag", "\"later\"")
			io.WriteString(w, "ss://aes-128-gcm:b@127.0.0.1:19002#Later")
			return
		}
		w.Header().Set("ETag", "\"preview\"")
		w.Header().Set("subscription-userinfo", "upload=10; download=20; total=100")
		io.WriteString(w, `proxies:
  - {name: Preview, type: socks5, server: 127.0.0.1, port: 19001}
proxy-groups:
  - {name: Traffic, type: select, proxies: [Preview, DIRECT]}
rules:
  - MATCH,Traffic
`)
	}))
	defer server.Close()
	ctx, impl := context.Background(), backend.Native{}
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	preview, err := PrepareImport(ctx, path, cache, MissingRevision, server.URL, impl)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || preview.Result.Added != 1 || preview.Subscription == nil {
		t.Fatal("preview did not keep the downloaded subscription")
	}
	for _, name := range []string{path, cache} {
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("preview wrote %s: %v", filepath.Base(name), err)
		}
	}
	// Confirmation in the app runs in another process.
	wire, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	var confirmation PreparedImport
	if err := json.Unmarshal(wire, &confirmation); err != nil {
		t.Fatal(err)
	}
	receipt, err := CommitPreparedImport(ctx, path, cache, confirmation, impl)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || receipt.Added != 1 || len(receipt.Notes) == 0 || !strings.HasPrefix(receipt.Notes[0], "已添加订阅") {
		t.Fatalf("confirmation did not use the preview, requests=%d", requests.Load())
	}
	config, err := engine.Decode(strings.NewReader(receipt.Text))
	if err != nil || len(config.Subscriptions) != 1 {
		t.Fatalf("missing saved subscription: %v", err)
	}
	sub := config.Subscriptions[0]
	saved, err := LoadSnapshot(cache, sub)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Updated != preview.Subscription.Snapshot.Updated || len(saved.Nodes) != 1 || saved.Nodes[0].Name != "Preview" ||
		len(saved.Groups) != 1 || saved.Groups[0].Members[0] != "Preview" || len(saved.Rules) != 1 ||
		saved.Validators == nil || saved.Validators.ETag != "\"preview\"" ||
		saved.Usage == nil || saved.Usage.Used == nil || *saved.Usage.Used != 30 {
		t.Fatal("saved snapshot changed the previewed routing, validator or quota")
	}
	next, _, err := Fetch(ctx, sub, impl, nil)
	if err != nil || requests.Load() != 2 || next.Nodes[0].Name != "Later" {
		t.Fatalf("fixture did not offer a different response after confirmation: %v", err)
	}
}

func TestPreparedImportCannotOverwriteNewerProfileOrCache(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		io.WriteString(w, "ss://aes-128-gcm:b@127.0.0.1:19002#Preview")
	}))
	defer server.Close()
	ctx, impl := context.Background(), backend.Native{}
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	config := engine.Default()
	sub := engine.Subscription{Name: "existing", URL: server.URL}
	config.Subscriptions = []engine.Subscription{sub}
	original, _ := json.Marshal(config)
	revision, err := CommitConfig(ctx, path, cache, MissingRevision, original, impl)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSnapshot(cache, sub, &Snapshot{Nodes: []outbound.Node{node("Previous")}}); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareImport(ctx, path, cache, revision, server.URL, impl)
	if err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(dir, "other.json")
	if err := os.WriteFile(otherPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CommitPreparedImport(ctx, otherPath, cache, prepared, impl); err == nil {
		t.Fatal("confirmation accepted a preview for another profile with the same revision")
	}
	if other, err := os.ReadFile(otherPath); err != nil || !bytes.Equal(other, original) {
		t.Fatalf("confirmation changed the other profile: %v", err)
	}
	if err := SaveSnapshot(cache, sub, &Snapshot{Nodes: []outbound.Node{node("Refreshed")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := CommitPreparedImport(ctx, path, cache, prepared, impl); !errors.Is(err, ErrImportSnapshotChanged) {
		t.Fatalf("confirmation should reject a changed cache: %v", err)
	}
	if doc, err := ReadDocument(path); err != nil || !bytes.Equal(doc.Bytes, original) {
		t.Fatalf("stale confirmation changed the profile: %v", err)
	}
	config.Subscriptions[0].Alias = "User edit"
	edited, _ := json.Marshal(config)
	if _, err := CommitConfig(ctx, path, cache, revision, edited, impl); err != nil {
		t.Fatal(err)
	}
	if _, err := CommitPreparedImport(ctx, path, cache, prepared, impl); !errors.Is(err, ErrConfigurationChanged) {
		t.Fatalf("confirmation should reject a changed profile: %v", err)
	}
	snapshot, err := LoadSnapshot(cache, sub)
	if err != nil || len(snapshot.Nodes) != 1 || snapshot.Nodes[0].Name != "Refreshed" || requests.Load() != 1 {
		t.Fatalf("stale confirmation made a network request or replaced the refreshed cache: %v", err)
	}
	if paths, err := filepath.Glob(filepath.Join(cache, "subscriptions", "*.json")); err != nil || len(paths) != 1 {
		t.Fatalf("stale confirmation left a staged snapshot: %v", err)
	}
}

func TestReimportRollsBackStagedSnapshotWhenConfigCannotBeReplaced(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission failure requires a non-root user")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ss://aes-128-gcm:b@127.0.0.1:19002#New")
	}))
	defer server.Close()
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	config := engine.Default()
	sub := engine.Subscription{Name: "existing", URL: server.URL}
	config.Subscriptions = []engine.Subscription{sub}
	data, _ := json.Marshal(config)
	ctx, impl := context.Background(), backend.Native{}
	initial, err := CommitConfig(ctx, path, cache, MissingRevision, data, impl)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSnapshot(cache, sub, &Snapshot{Nodes: []outbound.Node{node("Previous")}}); err != nil {
		t.Fatal(err)
	}
	snapshot := SnapshotPath(cache, sub)
	previous, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, err := CommitImport(ctx, path, cache, initial, server.URL, impl); !errors.Is(err, os.ErrPermission) ||
		!strings.Contains(err.Error(), filepath.Join(dir, ".tmp-")) {
		t.Fatalf("import should fail when replacing the profile: %v", err)
	}
	for filename, want := range map[string][]byte{path: data, snapshot: previous} {
		if got, err := os.ReadFile(filename); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("failed import rewrote %s: %v", filepath.Base(filename), err)
		}
	}
	files, err := filepath.Glob(filepath.Join(cache, "subscriptions", "*.json"))
	if err != nil || len(files) != 1 || files[0] != snapshot {
		t.Fatalf("staged import file leaked: %v, %v", files, err)
	}
}
