package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
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
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// The source breaks: the last snapshot stays in use and the error shows.
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
