package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
)

func TestReplacementRejectsDanglingReferences(t *testing.T) {
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	impl := backend.Native{}
	ctx := context.Background()
	base := engine.Default()
	base.Nodes = []outbound.Node{node("Manual")}
	base.Rules = []engine.Rule{{Type: engine.RuleMatch, Via: "Manual"}}
	baseBytes, _ := json.Marshal(base)
	expected, err := CommitConfig(ctx, path, cache, MissingRevision, baseBytes, impl)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		name, hint string
		edit       func(*engine.Config)
	}{
		{"selected", "选定出站", func(c *engine.Config) { c.Selected = "Missing" }},
		{"removed node", "第 1 条规则", func(c *engine.Config) { c.Nodes = nil }},
		{"group member", "不存在的成员", func(c *engine.Config) {
			c.Groups = []engine.Group{{Name: "Select", Type: engine.GroupSelect, Members: []string{"Missing", "Manual"}}}
		}},
		{"group selection", "不在成员列表", func(c *engine.Config) {
			c.Groups = []engine.Group{{Name: "Select", Type: engine.GroupSelect, Members: []string{"Manual"}, Selected: "DIRECT"}}
		}},
		{"rule set", "不存在的规则集", func(c *engine.Config) {
			c.Rules = []engine.Rule{{Type: engine.RuleRuleSet, Value: "Missing", Via: "DIRECT"}}
		}},
		{"local rule set", "unavailable.yaml", func(c *engine.Config) {
			c.RuleSets = []engine.RuleSet{{Name: "local", Path: filepath.Join(dir, "unavailable.yaml")}}
			c.Rules = []engine.Rule{{Type: engine.RuleRuleSet, Value: "local", Via: "DIRECT"}}
		}},
		{"DNS resolver", "domain_resolver", func(c *engine.Config) {
			c.Nodes[0].Options = json.RawMessage(`{"domain_resolver":{"server":"absent"}}`)
		}},
		{"detour", "前置节点", func(c *engine.Config) {
			c.Nodes[0].Options = json.RawMessage(`{"detour":"Missing"}`)
		}},
		{"detour cycle", "形成循环", func(c *engine.Config) {
			c.Nodes[0].Options = json.RawMessage(`{"detour":"Manual"}`)
		}},
	} {
		t.Run(sample.name, func(t *testing.T) {
			candidate := base
			candidate.Nodes = append([]outbound.Node(nil), base.Nodes...)
			sample.edit(&candidate)
			data, _ := json.Marshal(candidate)
			if _, err := CommitConfig(ctx, path, cache, expected, data, impl); err == nil || !strings.Contains(err.Error(), sample.hint) {
				t.Fatalf("candidate should fail with %q: %v", sample.hint, err)
			}
			if actual, err := os.ReadFile(path); err != nil || !bytes.Equal(actual, baseBytes) {
				t.Fatalf("invalid candidate replaced profile: %v", err)
			}
		})
	}
}

func TestPausedSourceOnlyAllowsInheritedReferences(t *testing.T) {
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	impl := backend.Native{}
	ctx := context.Background()
	config := engine.Default()
	sub := engine.Subscription{Name: "fixture", URL: "https://example.test/sub"}
	config.Subscriptions = []engine.Subscription{sub}
	config.Rules = []engine.Rule{{Type: engine.RuleDomain, Value: "existing.test", Via: "Cached"}}
	if err := SaveSnapshot(cache, sub, &Snapshot{Nodes: []outbound.Node{node("Cached")}}); err != nil {
		t.Fatal(err)
	}
	commit := func(expected string) (string, error) {
		data, _ := json.Marshal(config)
		return CommitConfig(ctx, path, cache, expected, data, impl)
	}
	active, err := commit(MissingRevision)
	if err != nil {
		t.Fatal(err)
	}
	config.Subscriptions[0].Paused = true
	paused, err := commit(active)
	if err != nil {
		t.Fatalf("existing reference blocked an intentional pause: %v", err)
	}
	config.MaxDialAttempts = 2
	edited, err := commit(paused)
	if err != nil {
		t.Fatalf("an unrelated edit was blocked by an existing unavailable route: %v", err)
	}
	config.Rules = append(config.Rules, engine.Rule{Type: engine.RuleDomain, Value: "new.test", Via: "Cached"})
	if _, err := commit(edited); err == nil || !strings.Contains(err.Error(), "第 2 条") {
		t.Fatalf("a newly authored dangling rule should fail: %v", err)
	}
}

func TestLegacyValidationFailureKeepsProfileAndSnapshots(t *testing.T) {
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	validate := func(c engine.Config) error { return engine.Validate(c, backend.Native{}) }
	sub := engine.Subscription{Name: "old", URL: "https://example.test/sub"}
	if err := SaveSnapshot(cache, sub, &Snapshot{Nodes: []outbound.Node{node("From cache")}}); err != nil {
		t.Fatal(err)
	}
	snapshotPath := SnapshotPath(cache, sub)
	savedSnapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	old := []byte(`{"version":0,"subscriptions":[{"name":"old","url":"https://example.test/sub"}]}`)
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	good, err := Load(path, cache, validate)
	if err != nil || good.User.Version != engine.ConfigVersion || good.Fallback {
		t.Fatalf("legacy profile did not load: %v", err)
	}
	broken := []byte(`{"version":0,"selected":"Missing","subscriptions":[{"name":"old","url":"https://example.test/sub"}]}`)
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(path, cache, validate); err == nil || !strings.Contains(err.Error(), "选定出站") {
		t.Fatalf("read-only check accepted the broken legacy configuration: %v", err)
	}
	loaded, err := Load(path, cache, validate)
	if err != nil || !loaded.Fallback || loaded.Revision != good.Revision || len(loaded.Merged.Nodes) != 1 ||
		!strings.Contains(loaded.Warnings[0], "选定出站") {
		t.Fatalf("failed legacy validation did not fall back: %+v, %v", loaded, err)
	}
	for file, expected := range map[string][]byte{path: broken, lastGoodPath(cache): old, snapshotPath: savedSnapshot} {
		if actual, err := os.ReadFile(file); err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("legacy failure rewrote %s: %v", filepath.Base(file), err)
		}
	}
}

func TestMergedDetourStaysWithItsSubscription(t *testing.T) {
	config := engine.Default()
	config.Nodes = []outbound.Node{node("Gateway")}
	config.Subscriptions = []engine.Subscription{{Name: "fixture"}}
	entry := node("Remote")
	entry.Options = json.RawMessage(`{"detour":"Gateway"}`)
	snapshot := &Snapshot{Nodes: []outbound.Node{node("Gateway"), entry}}
	merged, _ := Merge(config, map[string]*Snapshot{"fixture": snapshot})
	if len(merged.Nodes) != 3 || merged.Nodes[1].Name != "Gateway (fixture 2)" ||
		string(merged.Nodes[2].Options) != `{"detour":"Gateway (fixture 2)"}` || string(snapshot.Nodes[1].Options) != `{"detour":"Gateway"}` {
		t.Fatalf("the remote detour did not follow its own gateway: %+v", merged.Nodes)
	}
}

func TestPruneExpiredSnapshotsRetainsEveryManagedReference(t *testing.T) {
	dir := t.TempDir()
	path, cache := filepath.Join(dir, "config.json"), filepath.Join(dir, "cache")
	previous := time.Now().Add(-2 * snapshotGracePeriod)
	makeSnapshot := func(name, key string, aged bool) engine.Subscription {
		t.Helper()
		sub := engine.Subscription{Name: name, URL: "https://example.test/" + name, SnapshotKey: key}
		if err := SaveSnapshot(cache, sub, &Snapshot{Nodes: []outbound.Node{node(name)}}); err != nil {
			t.Fatal(err)
		}
		if aged {
			if err := os.Chtimes(SnapshotPath(cache, sub), previous, previous); err != nil {
				t.Fatal(err)
			}
		}
		return sub
	}
	active := makeSnapshot("active", strings.Repeat("a", 32), true)
	paused := makeSnapshot("paused", "", true)
	paused.Paused = true
	rollback := makeSnapshot("rollback", strings.Repeat("b", 32), true)
	shared := makeSnapshot("shared", "", true)
	expired := makeSnapshot("removed", strings.Repeat("c", 32), true)
	new := makeSnapshot("new staging file", "", false)
	writeProfile := func(file string, subs ...engine.Subscription) {
		t.Helper()
		config := engine.Default()
		config.Subscriptions = subs
		data, _ := json.Marshal(config)
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeProfile(path, active, paused)
	writeProfile(lastGoodPath(cache), rollback)
	peer := filepath.Join(dir, "other.json")
	if err := os.WriteFile(peer, []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PruneSnapshots(path, cache); err == nil {
		t.Fatal("an unreadable profile did not stop cleanup")
	}
	if _, err := os.Stat(SnapshotPath(cache, expired)); err != nil {
		t.Fatal("cleanup removed a snapshot while references were unknown")
	}
	writeProfile(peer, shared)
	if err := PruneSnapshots(path, cache); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(SnapshotPath(cache, expired)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired unreferenced snapshot still exists: %v", err)
	}
	for _, sub := range []engine.Subscription{active, paused, rollback, shared, new} {
		if _, err := LoadSnapshot(cache, sub); err != nil {
			t.Fatalf("needed snapshot %s was removed: %v", sub.Name, err)
		}
	}
}
