package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/netmon"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/profile"
	"mac-proxy/internal/sysproxy"
)

func echo(t *testing.T) string {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String()
}

func TestSubscriptionRefreshAndHotReload(t *testing.T) {
	var links atomic.Value
	links.Store("ss://aes-128-gcm:a@127.0.0.1:1#One\n")
	var status atomic.Int32
	status.Store(http.StatusOK)
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		w.Write([]byte(links.Load().(string)))
	})}
	go server.Serve(listener)
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	config := engine.Default()
	config.Subscriptions = []engine.Subscription{{Name: "air", URL: "http://" + listener.Addr().String() + "/sub"}}
	data, _ := json.Marshal(config)
	os.WriteFile(path, data, 0o600)

	s, err := Open(path, filepath.Join(dir, "cache"), backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(sysproxy.Target{}); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	names := func() map[string]bool {
		set := map[string]bool{}
		for _, node := range s.Status().Nodes {
			set[node.Name] = true
		}
		return set
	}
	s.RefreshSubscriptions(context.Background(), false) // first download
	if !names()["One"] {
		t.Fatalf("subscription nodes missing: %+v", s.Status())
	}
	sub := s.Status().Subscriptions[0]
	if sub.Nodes != 1 || sub.Updated == 0 || sub.Error != "" {
		t.Fatalf("subscription status %+v", sub)
	}
	s.Engine().SetPolicy(engine.Policy{Mode: "global", Selected: "DIRECT"})

	// A connection opened now must survive the reload.
	conn, err := s.Dial(context.Background(), "test", echo(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	before := s.Engine()

	links.Store("ss://aes-128-gcm:a@127.0.0.1:1#One\nss://aes-128-gcm:b@127.0.0.1:2#Two\n")
	s.RefreshSubscriptions(context.Background(), false)
	if names()["Two"] {
		t.Fatal("a fresh snapshot must not be refetched before its interval")
	}
	s.RefreshSubscriptions(context.Background(), true)
	if !names()["Two"] || s.Engine() == before {
		t.Fatalf("forced refresh did not reload: %v", names())
	}
	if policy := s.Status().Policy; policy.Mode != "global" {
		t.Fatalf("runtime policy lost on reload: %+v", policy)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte("still"))
	buffer := make([]byte, 5)
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "still" {
		t.Fatalf("connection dropped by reload: %q %v", buffer, err)
	}

	// None of these failures may replace the last usable snapshot.
	cachePath := profile.SnapshotPath(filepath.Join(dir, "cache"), config.Subscriptions[0])
	good, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []struct {
		name   string
		status int32
		body   string
	}{
		{"login page", http.StatusOK, "<!doctype html><html><title>Sign in</title></html>"},
		{"limit", http.StatusTooManyRequests, "ss://aes-128-gcm:a@127.0.0.1:1#RateLimited"},
		{"invalid content", http.StatusOK, "not a proxy configuration"},
		{"empty subscription", http.StatusOK, "proxies: []\n"},
	} {
		t.Run(failure.name, func(t *testing.T) {
			status.Store(failure.status)
			links.Store(failure.body)
			s.RefreshSubscriptions(context.Background(), true)
			after, err := os.ReadFile(cachePath)
			if err != nil || !bytes.Equal(after, good) || !names()["Two"] || s.Status().Subscriptions[0].Error == "" {
				t.Fatal("invalid response replaced the cached subscription or was not reported")
			}
		})
	}

	// The source disconnects: the last snapshot stays in use and the error shows.
	server.Close()
	s.RefreshSubscriptions(context.Background(), true)
	if !names()["Two"] || s.Status().Subscriptions[0].Error == "" {
		t.Fatalf("failed refresh: %+v", s.Status().Subscriptions)
	}

	// A restart works offline from the cached snapshot.
	s.Close()
	again, err := Open(path, filepath.Join(dir, "cache"), backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if len(again.Config().Nodes) != 2 {
		t.Fatalf("cached snapshot not used at start: %+v", again.Config().Nodes)
	}
}

func TestSubscriptionRefreshDiscardsPreviousNetworkResponse(t *testing.T) {
	started, canceled := make(chan struct{}), make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
			<-r.Context().Done()
			close(canceled)
			return
		}
		_, _ = io.WriteString(w, "ss://aes-128-gcm:a@127.0.0.1:1#Fresh\n")
	}))
	defer server.Close()
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	sub := engine.Subscription{Name: "fixture", URL: server.URL}
	config := engine.Default()
	config.Subscriptions = []engine.Subscription{sub}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := profile.SaveSnapshot(cache, sub, &profile.Snapshot{
		Updated: time.Now().UnixMilli(),
		Nodes:   []outbound.Node{{Name: "Cached", Type: "socks5", Server: "127.0.0.1:1"}},
	}); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, cache, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Start(sysproxy.Target{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	wait := func(done <-chan struct{}, message string) {
		t.Helper()
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal(message)
		}
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		s.RefreshSubscriptions(ctx, true)
	}()
	wait(started, "refresh did not reach subscription server")
	s.networkChanged(netmon.Event{Kind: "network", At: time.Now()})
	wait(canceled, "network change did not cancel the old HTTP request")
	wait(finished, "old refresh did not exit")
	snapshot, err := profile.LoadSnapshot(cache, sub)
	if err != nil || len(snapshot.Nodes) != 1 || snapshot.Nodes[0].Name != "Cached" || s.Status().Subscriptions[0].Error != "" {
		t.Fatal("canceled refresh replaced the cache or appeared as a provider error")
	}
	s.RefreshSubscriptions(ctx, true)
	snapshot, err = profile.LoadSnapshot(cache, sub)
	active := s.Status()
	if err != nil || len(snapshot.Nodes) != 1 || snapshot.Nodes[0].Name != "Fresh" ||
		!slices.ContainsFunc(active.Nodes, func(node engine.NodeSummary) bool { return node.Name == "Fresh" }) ||
		slices.ContainsFunc(active.Nodes, func(node engine.NodeSummary) bool { return node.Name == "Cached" }) {
		t.Fatalf("refresh on the new network did not update the cache and active nodes: requests=%d, nodes=%+v, error=%v", requests.Load(), active.Nodes, err)
	}
}

func TestTUNOperationTracksCompletionAndStop(t *testing.T) {
	s, err := Open("", t.TempDir(), backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Start(sysproxy.Target{}); err != nil {
		t.Fatal(err)
	}
	for _, result := range []error{nil, errors.New("已取消授权")} {
		finish := make(chan error, 1)
		if err := s.startTUNOperation("enable", func() error {
			select {
			case err := <-finish:
				return err
			case <-s.ctx.Done():
				return s.ctx.Err()
			}
		}); err != nil {
			t.Fatal(err)
		}
		if got := s.Status().TUN; got.Operation != "enable" || got.Error != "" {
			t.Fatalf("authorization wait was not reported as in progress: %+v", got)
		}
		if err := s.StartTUNServiceChange(true); !errors.Is(err, ErrTUNBusy) {
			t.Fatalf("concurrent helper request was not refused: %v", err)
		}
		finish <- result
		s.tunTask.Wait()
		if got := s.Status().TUN; got.Operation != "" || (result == nil) != (got.Error == "") {
			t.Fatalf("operation survived completion or hid authorization failure: %+v", got)
		}
	}
	if err := s.startTUNOperation("install-helper", func() error {
		<-s.ctx.Done()
		return s.ctx.Err()
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if got := s.Status().TUN; got.Operation != "" || got.Error != "" {
		t.Fatalf("stopped core still reported an authorization operation: %+v", got)
	}
}

func TestReloadRejectsBrokenConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"mode":"rule","selected":"DIRECT","nodes":[],"rules":[]}`), 0o600)
	s, err := Open(path, filepath.Join(dir, "cache"), backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(sysproxy.Target{}); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before := s.Engine()
	// A failed explicit reload keeps the current engine and reports the error.
	os.WriteFile(path, []byte(`{broken`), 0o600)
	if err := s.Reload(); err == nil {
		t.Fatal("broken configuration was accepted")
	}
	if s.Engine() != before {
		t.Fatal("failed reload replaced the running engine")
	}
	os.WriteFile(path, []byte(`{"socksPort":4242,"httpPort":4243,"mode":"rule","selected":"DIRECT","nodes":[],"rules":[]}`), 0o600)
	if err := s.Reload(); err != ErrPortsChanged {
		t.Fatalf("port change: %v", err)
	}
}

func TestResourceLimitsApplyOnlyOnRestart(t *testing.T) {
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	config := engine.Default()
	save := func() {
		t.Helper()
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	start := func() *Supervisor {
		t.Helper()
		s, err := Open(path, cache, backend.Native{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		if err := s.Start(sysproxy.Target{}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	save()
	s := start()
	defaults := s.CompactStatus().Resources.ResourceLimits
	config.Resources = defaults
	save()
	if err := s.Reload(); err != nil {
		t.Fatalf("explicit defaults must reload: %v", err)
	}
	config.Resources = engine.ResourceLimits{ConnectionLimit: 16, UDPSessionLimit: 32, UDPOpenLimit: 1, EndpointDialLimit: 4, UDPIdleTimeoutSec: 45}
	save()
	before := s.Engine()
	if err := s.Reload(); !errors.Is(err, ErrResourcesChanged) || s.Engine() != before {
		t.Fatalf("changing resource limits must keep the running engine: %v", err)
	}
	if got := s.CompactStatus().Resources.ResourceLimits; got != defaults {
		t.Fatalf("pending values replaced the running limits: %+v", got)
	}
	s.Close()
	s = start()
	if got := s.CompactStatus().Resources.ResourceLimits; got != config.Resources {
		t.Fatalf("restart did not apply the saved limits: %+v", got)
	}
	config.Resources.UDPSessionLimit = -1
	save()
	if err := s.Reload(); err == nil || errors.Is(err, ErrResourcesChanged) {
		t.Fatalf("invalid limits must fail validation: %v", err)
	}
}

func TestAutoPolicySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	config := engine.Default()
	config.Nodes = []outbound.Node{{Name: "HK", Type: "socks5", Server: "127.0.0.1:1"}}
	save := func() {
		t.Helper()
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	start := func() *Supervisor {
		t.Helper()
		s, err := Open(path, filepath.Join(dir, "cache"), backend.Native{})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Start(sysproxy.Target{}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	first := start()
	if err := first.SetPolicy(engine.Policy{Mode: "auto", Selected: "DIRECT", Auto: &engine.AutoConfig{
		Region: "HK", Groups: []engine.AutoGroup{{Name: "First", Nodes: []string{"HK"}}},
	}}); err != nil {
		first.Close()
		t.Fatal(err)
	}
	first.Close()
	second := start()
	defer second.Close()
	if got := second.Engine().Runtime().Policy; got.Mode != "auto" {
		t.Fatalf("automatic policy not restored: %+v", got)
	}
	nodes := config.Nodes
	config.Nodes = nil
	save()
	if err := second.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := second.Engine().Decide("example.test:443"); got != "REJECT" {
		t.Fatalf("missing automatic node should block the route, got %s", got)
	}
	config.Nodes = nodes
	save()
	if err := second.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := second.Engine().Runtime().Policy; got.Mode != "auto" {
		t.Fatalf("automatic policy not recovered: %+v", got)
	}
	if err := second.SetPolicy(engine.Policy{Mode: "rule", Selected: "DIRECT"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(second.autoPolicyPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manual mode should clear the saved automatic policy: %v", err)
	}
}

func TestUndoRouteRestoresThePreviousManualPolicy(t *testing.T) {
	config := engine.Default()
	config.Nodes = []outbound.Node{{Name: "node", Type: "socks5", Server: "127.0.0.1:1"}}
	config.Groups = []engine.Group{{Name: "pick", Type: engine.GroupSelect, Members: []string{"node", "DIRECT"}}}
	core, err := engine.New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	supervisor := &Supervisor{}
	supervisor.current.Store(core)

	if supervisor.canUndoRoute() {
		t.Fatal("a fresh supervisor must not offer undo")
	}
	before := core.Runtime()
	beforePolicy := before.Policy
	if err := supervisor.SetPolicy(engine.Policy{Mode: "global", Selected: "node"}); err != nil {
		t.Fatal(err)
	}
	supervisor.RememberRoute(before)
	if !supervisor.canUndoRoute() {
		t.Fatal("undo was not remembered")
	}

	policy, ok := supervisor.UndoRoute()
	if !ok {
		t.Fatal("undo reported nothing to restore")
	}
	if policy != beforePolicy {
		t.Fatalf("undo reported %+v, want %+v", policy, beforePolicy)
	}
	if got := core.Runtime().Policy; got != beforePolicy {
		t.Fatalf("policy after undo is %+v, want %+v", got, beforePolicy)
	}
	if supervisor.canUndoRoute() {
		t.Fatal("undo must be one level only")
	}
}

func TestUndoRouteIsOneStepOnly(t *testing.T) {
	config := engine.Default()
	config.Nodes = []outbound.Node{{Name: "one", Type: "socks5", Server: "127.0.0.1:1"},
		{Name: "two", Type: "socks5", Server: "127.0.0.1:1"}}
	core, err := engine.New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	supervisor := &Supervisor{}
	supervisor.current.Store(core)

	for _, name := range []string{"one", "two"} {
		snapshot := core.Runtime()
		if err := supervisor.SetPolicy(engine.Policy{Mode: "global", Selected: name}); err != nil {
			t.Fatal(err)
		}
		supervisor.RememberRoute(snapshot)
	}
	if _, ok := supervisor.UndoRoute(); !ok {
		t.Fatal("first undo failed")
	}
	if got := core.Runtime().Policy.Selected; got != "one" {
		t.Fatalf("undo went back to %q, want the immediately previous choice %q", got, "one")
	}
	if _, ok := supervisor.UndoRoute(); ok {
		t.Fatal("a second undo must not go further back")
	}
}
