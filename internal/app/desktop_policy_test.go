package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/profile"
	"mac-proxy/internal/sysproxy"
)

func routeFixture(t *testing.T, name string, probe func() bool) outbound.Node {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusBadRequest)
			return
		}
		conn, stream, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		stream.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := stream.Flush(); err != nil {
			return
		}
		req, err := http.ReadRequest(stream.Reader)
		if err != nil {
			return
		}
		req.Body.Close()
		if req.URL.Path == "/probe" && !probe() {
			stream.WriteString("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
		} else {
			fmt.Fprintf(stream, "HTTP/1.1 204 No Content\r\nX-Fixture-Exit: %s\r\nConnection: close\r\n\r\n", name)
		}
		stream.Flush()
	}))
	t.Cleanup(server.Close)
	return outbound.Node{Name: name, Type: "http", Server: server.Listener.Addr().String()}
}

func desktopRouteFixture(t *testing.T, config engine.Config) (func(*engine.Policy) *Supervisor, string) {
	t.Helper()
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, raw) {
			t.Errorf("outbound selection modified the original profile: %v", err)
		}
	})
	return func(initial *engine.Policy) *Supervisor {
		t.Helper()
		s, err := Open(path, cache, backend.Native{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		s.EnableDesktopRouting(initial)
		if err := s.Start(sysproxy.Target{}); err != nil {
			t.Fatal(err)
		}
		return s
	}, cache
}

func fixtureExit(ctx context.Context, s *Supervisor, target string) (string, error) {
	conn, err := s.Dial(ctx, "route fixture", target)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = fmt.Fprintf(conn, "GET /route HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if err != nil {
		return "", err
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	return res.Header.Get("X-Fixture-Exit"), nil
}

func waitRouteStatus(t *testing.T, s *Supervisor, ready func(engine.Status) bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if ready(s.Engine().CompactStatus()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("routing status did not reach the expected state")
}

func TestDesktopFastestAndManualOutboundSurviveRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fastProbe, slowProbe := make(chan struct{}), make(chan struct{})
	allow := func(gate chan struct{}) bool {
		select {
		case <-gate:
			return true
		case <-ctx.Done():
			return false
		}
	}
	slow := routeFixture(t, "Slow", func() bool { return allow(slowProbe) })
	fast := routeFixture(t, "Fast", func() bool { return allow(fastProbe) })
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Fixture-Exit", "direct")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer direct.Close()
	config := engine.Default()
	config.Nodes = []outbound.Node{slow, fast}
	config.Rules = []engine.Rule{{Type: engine.RuleMatch, Via: "DIRECT"}}
	config.Health = &engine.Health{URL: "http://192.0.2.10/probe"}
	start, cache := desktopRouteFixture(t, config)
	s := start(nil)
	target := direct.Listener.Addr().String()
	waitRouteStatus(t, s, func(status engine.Status) bool {
		return status.Policy.Mode == "fastest" && status.Auto.Probing && status.Auto.Node == ""
	})
	if got := s.Engine().Decide(target); got != "REJECT" {
		t.Fatalf("unmeasured startup traffic could escape via %s", got)
	}
	outcome := make(chan string, 1)
	go func() {
		exit, err := fixtureExit(ctx, s, target)
		if err != nil {
			exit = err.Error()
		}
		outcome <- exit
	}()
	select {
	case got := <-outcome:
		t.Fatalf("request did not wait for a measured proxy: %s", got)
	case <-time.After(45 * time.Millisecond):
	}
	close(fastProbe)
	select {
	case got := <-outcome:
		if got != "Fast" {
			t.Fatalf("first request reached %q instead of the first verified exit", got)
		}
	case <-ctx.Done():
		t.Fatal("request did not resume after a successful probe")
	}
	time.Sleep(45 * time.Millisecond)
	close(slowProbe)
	waitRouteStatus(t, s, func(status engine.Status) bool { return !status.Auto.Probing && status.Auto.Node == "Fast" })
	assertExit := func(want string) {
		t.Helper()
		if got, err := fixtureExit(ctx, s, target); err != nil || got != want {
			t.Fatalf("request used %q, want %q: %v", got, want, err)
		}
	}
	assertExit("Fast")
	if err := s.SetPolicy(engine.Policy{Mode: "global", Selected: "Slow"}); err != nil {
		t.Fatal(err)
	}
	assertExit("Slow")
	s.Close()
	s = start(nil)
	assertExit("Slow")
	for _, mode := range []string{"rule", "direct"} {
		if err := s.SetPolicy(engine.Policy{Mode: mode, Selected: "DIRECT"}); err != nil {
			t.Fatal(err)
		}
		s.Close()
		s = start(nil)
		if got := s.Engine().CompactStatus().Policy.Mode; got != mode {
			t.Fatalf("restarted in %s mode, want %s", got, mode)
		}
		assertExit("direct")
	}
	s.Close()
	s = start(&engine.Policy{Mode: "global", Selected: "Fast", ExpectedProbeKey: config.ProbeKeys()["Fast"]})
	assertExit("Fast")
	if got := DesktopStartupPolicy(profile.Loaded{User: config, Merged: config}, cache); got.Mode != "global" || got.Selected != "Fast" {
		t.Fatalf("stopped summary did not reflect startup-node selection: %+v", got)
	}
}

func TestDesktopFastestBlocksWhenNodesAreDownAndRecovers(t *testing.T) {
	var alive atomic.Bool
	node := routeFixture(t, "Recoverable", alive.Load)
	config := engine.Default()
	config.Nodes = []outbound.Node{node}
	config.Health = &engine.Health{URL: "http://192.0.2.10/probe"}
	start, _ := desktopRouteFixture(t, config)
	s := start(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	target := "127.0.0.1:1"
	if _, err := fixtureExit(ctx, s, target); !errors.Is(err, outbound.ErrRejected) {
		t.Fatalf("unavailable automatic route tried to connect directly: %v", err)
	}
	if conn, err := s.DialPacket(ctx, "route fixture", target); !errors.Is(err, outbound.ErrRejected) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("unavailable automatic UDP route tried to connect directly: %v", err)
	}
	alive.Store(true)
	s.Engine().Probe(ctx, []string{node.Name})
	if got, err := fixtureExit(ctx, s, target); err != nil || got != node.Name {
		t.Fatalf("recovered exit was not selected: %q %v", got, err)
	}
}

func TestDesktopPolicyPreservesExplicitConfigAndStableSelection(t *testing.T) {
	config := engine.Default()
	config.Rules = []engine.Rule{{Type: engine.RuleDomain, Value: "local.test", Via: "DIRECT"}}
	config.Nodes = []outbound.Node{{Name: "Beta (2)", Type: "http", Server: "127.0.0.1:1"}}
	key := engine.SourceOutboundID("beta", "Shared", false)
	config.OutboundIDs = map[string]string{"Beta (2)": key}
	loaded := profile.Loaded{User: config, Merged: config}
	if mode := chooseDesktopPolicy(loaded, nil, nil).Mode; mode != "rule" {
		t.Fatalf("explicit routing rules must be preserved, got %s", mode)
	}
	saved := &desktopPolicy{Policy: engine.Policy{Mode: "global", Selected: "Shared"}, SelectedID: key}
	if selected := chooseDesktopPolicy(loaded, saved, nil).Selected; selected != "Beta (2)" {
		t.Fatalf("saved node did not follow its provider identity: %s", selected)
	}
	loaded.Merged.Nodes[0].Name = "Shared"
	if selected := chooseDesktopPolicy(loaded, saved, nil).Selected; selected != "REJECT" {
		t.Fatalf("missing saved node selected a different proxy: %s", selected)
	}
}

func TestSaveDesktopPresetChangesOnlyNextStartupPolicy(t *testing.T) {
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	config := engine.Default()
	config.Rules = []engine.Rule{{Type: engine.RuleDomain, Value: "local.test", Via: "DIRECT"}}
	config.Groups = []engine.Group{
		{Name: "Backup", Type: engine.GroupFallback, Members: []string{"DIRECT"}},
		{Name: "Manual", Type: engine.GroupSelect, Members: []string{"DIRECT"}},
	}
	document, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"fastest", "direct", "rule"} {
		if err := SaveDesktopMode(context.Background(), path, cache, mode, "", backend.Native{}); err != nil {
			t.Fatal(err)
		}
		if got := DesktopStartupPolicy(profile.Loaded{User: config, Merged: config}, cache); got.Mode != mode {
			t.Fatalf("saved mode %q, want %q", got.Mode, mode)
		}
	}
	if err := SaveDesktopMode(context.Background(), path, cache, "auto", "", backend.Native{}); err == nil {
		t.Fatal("accepted regional routing without a region")
	}
	for _, name := range []string{"", "missing", "Manual"} {
		if err := SaveDesktopMode(context.Background(), path, cache, "global", name, backend.Native{}); err == nil {
			t.Fatalf("accepted %q as a fallback group", name)
		}
	}
	if err := SaveDesktopMode(context.Background(), path, cache, "global", "Backup", backend.Native{}); err != nil {
		t.Fatal(err)
	}
	if got := DesktopStartupPolicy(profile.Loaded{User: config, Merged: config}, cache); got.Mode != "global" || got.Selected != "Backup" {
		t.Fatalf("saved fallback policy %+v", got)
	}
	if saved, err := os.ReadFile(path); err != nil || !bytes.Equal(saved, document) {
		t.Fatalf("the preset changed the user configuration: %v", err)
	}
}
