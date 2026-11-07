package app

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/profile"
	"mac-proxy/internal/sysproxy"
)

func TestSubscriptionReorderKeepsExitAndProbeIdentity(t *testing.T) {
	proxy := func(label string, delay time.Duration) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "expected CONNECT", http.StatusBadRequest)
				return
			}
			conn, stream, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			stream.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			stream.Flush()
			request, err := http.ReadRequest(stream.Reader)
			if err != nil {
				return
			}
			request.Body.Close()
			time.Sleep(delay)
			fmt.Fprintf(stream, "HTTP/1.1 204 No Content\r\nX-Fixture-Exit: %s\r\nConnection: close\r\n\r\n", label)
			stream.Flush()
		}))
		t.Cleanup(server.Close)
		return server
	}
	alphaExit, betaExit, newBetaExit := proxy("alpha", 12*time.Millisecond), proxy("beta", 30*time.Millisecond), proxy("beta-updated", 20*time.Millisecond)
	source := func(name string, exit *httptest.Server) (engine.Subscription, *atomic.Int32) {
		port := new(atomic.Int32)
		port.Store(int32(exit.Listener.Addr().(*net.TCPAddr).Port))
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, "proxies:\n  - {name: Shared, type: http, server: 127.0.0.1, port: %d}\n"+
				"proxy-groups:\n  - {name: Pool, type: select, proxies: [DIRECT, Shared]}\n", port.Load())
		}))
		t.Cleanup(server.Close)
		return engine.Subscription{Name: name, URL: server.URL}, port
	}
	alpha, _ := source("Alpha", alphaExit)
	beta, betaPort := source("Beta", betaExit)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	impl := backend.Native{}
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	config := engine.Default()
	config.Subscriptions = []engine.Subscription{alpha, beta}
	config.Health = &engine.Health{URL: "http://192.0.2.4/check"}
	config.Rules = []engine.Rule{
		{Type: engine.RuleIPCIDR, Value: "127.0.0.0/8", Via: "DIRECT"},
		{Type: engine.RuleMatch, Via: "SELECT"},
	}
	revision := profile.MissingRevision
	save := func() {
		t.Helper()
		raw, err := json.Marshal(config)
		if err == nil {
			revision, err = profile.CommitConfig(ctx, path, cache, revision, raw, impl)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	save()
	for _, sub := range config.Subscriptions {
		if _, err := profile.RefreshSnapshot(ctx, config, sub, path, cache, impl, nil); err != nil {
			t.Fatal(err)
		}
	}
	supervisor, err := Open(path, cache, impl)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Start(sysproxy.Target{}); err != nil {
		t.Fatal(err)
	}
	defer supervisor.Close()
	exit := func(want string) {
		t.Helper()
		conn, err := supervisor.Dial(ctx, "fixture", "192.0.2.4:80")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		io := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		io.WriteString("GET /route HTTP/1.1\r\nHost: 192.0.2.4\r\nConnection: close\r\n\r\n")
		if err := io.Flush(); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(io.Reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if got := response.Header.Get("X-Fixture-Exit"); got != want {
			t.Fatalf("traffic reached %q, want %q", got, want)
		}
	}
	node := func(name string) engine.NodeSummary {
		t.Helper()
		for _, node := range supervisor.CompactStatus().Nodes {
			if node.Name == name {
				return node
			}
		}
		t.Fatalf("no node %q", name)
		return engine.NodeSummary{}
	}
	reorder := func() {
		t.Helper()
		slices.Reverse(config.Subscriptions)
		save()
		if err := supervisor.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	if err := supervisor.SetPolicy(engine.Policy{Mode: "rule", Selected: "Shared"}); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Engine().SelectInGroup("Pool (Beta 2)", "Shared (Beta 2)"); err != nil {
		t.Fatal(err)
	}
	supervisor.Engine().Probe(ctx, nil)
	alphaBefore, betaBefore := node("Shared"), node("Shared (Beta 2)")
	if alphaBefore.HealthAt == 0 || betaBefore.HealthAt == 0 || alphaBefore.ProbeKey == betaBefore.ProbeKey {
		t.Fatal("both providers must have distinct measured results")
	}
	exit("alpha")
	reorder()
	if got := supervisor.CompactStatus().Policy.Selected; got != "Shared (Alpha 2)" {
		t.Fatalf("selection after reorder = %q", got)
	}
	exit("alpha")
	for _, item := range []struct {
		name string
		old  engine.NodeSummary
	}{{"Shared (Alpha 2)", alphaBefore}, {"Shared", betaBefore}} {
		if current := node(item.name); current.ProbeKey != item.old.ProbeKey || current.HealthAt != item.old.HealthAt ||
			current.LatencyMs != item.old.LatencyMs {
			t.Fatalf("wrong probe history attached to %q: %+v", item.name, current)
		}
	}
	foundGroup := false
	for _, group := range supervisor.CompactStatus().Groups {
		if group.Name == "Pool" {
			foundGroup = group.Selected == "Shared"
		}
	}
	if !foundGroup {
		t.Fatal("same-name Beta group lost its manual selection")
	}
	if err := supervisor.SetPolicy(engine.Policy{Mode: "global", Selected: "Shared", ExpectedProbeKey: alphaBefore.ProbeKey}); err == nil {
		t.Fatal("old display name was accepted as the other provider")
	}

	betaPort.Store(int32(newBetaExit.Listener.Addr().(*net.TCPAddr).Port))
	if result := supervisor.RefreshSubscription(ctx, beta.Key()); result.Succeeded != 1 {
		t.Fatalf("refresh failed: %+v", result)
	}
	if current := node("Shared"); current.ProbeKey == betaBefore.ProbeKey || current.HealthAt != 0 {
		t.Fatalf("new endpoint inherited the old probe: %+v", current)
	}
	if current := node("Shared (Alpha 2)"); current.HealthAt != alphaBefore.HealthAt {
		t.Fatal("refreshing Beta discarded Alpha's history")
	}
	exit("alpha")

	auto := engine.Policy{Mode: "auto", Auto: &engine.AutoConfig{Region: "HK", Groups: []engine.AutoGroup{
		{Name: "Beta", ProviderID: beta.Key(), Nodes: []string{"Shared"}},
		{Name: "Alpha", ProviderID: alpha.Key(), Nodes: []string{"Shared (Alpha 2)"}},
	}}}
	if err := supervisor.SetPolicy(auto); err != nil {
		t.Fatal(err)
	}
	for {
		if active := supervisor.CompactStatus().Auto; active != nil && active.Node == "Shared" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("Beta never became the selected automatic exit")
		case <-time.After(10 * time.Millisecond):
		}
	}
	exit("beta-updated")
	reorder()
	if active := supervisor.CompactStatus().Auto; active == nil || active.Node != "Shared (Beta 2)" {
		t.Fatalf("automatic exit did not survive the reorder: %+v", active)
	}
	exit("beta-updated")

	// An unchanged user-authored name must not silently bind to another
	// provider while a new revision is being applied.
	config.Rules[1].Via = "Shared"
	save()
	if err := supervisor.Reload(); err != nil {
		t.Fatal(err)
	}
	currentEngine := supervisor.Engine()
	slices.Reverse(config.Subscriptions)
	save()
	if err := supervisor.Reload(); err == nil || !strings.Contains(err.Error(), "订阅来源已变化") {
		t.Fatalf("reload accepted a rebound rule: %v", err)
	}
	if supervisor.Engine() != currentEngine {
		t.Fatal("rejected reload replaced the running engine")
	}
	exit("beta-updated")
}
