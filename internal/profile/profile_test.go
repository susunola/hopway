package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/outbound"
)

func node(name string) outbound.Node {
	return outbound.Node{Name: name, Type: "socks5", Server: "127.0.0.1:1080"}
}

func TestMerge(t *testing.T) {
	user := engine.Default()
	user.Nodes = []outbound.Node{node("HK")}
	user.Selected = "Proxy" // a group the subscription provides
	user.Subscriptions = []engine.Subscription{{Name: "air", URL: "https://air.test/sub"}}
	user.Rules = []engine.Rule{
		{Type: engine.RuleDomainSuffix, Value: "corp.test", Via: "DIRECT"},
		{Type: engine.RuleDomainSuffix, Value: "video.test", Via: "Proxy"},
		{Type: engine.RuleMatch, Via: "Proxy"},
	}
	snapshot := &Snapshot{
		Nodes:    []outbound.Node{node("HK"), node("JP")},
		Groups:   []engine.Group{{Name: "Proxy", Type: "select", Members: []string{"HK", "JP"}}},
		RuleSets: []engine.RuleSet{{Name: "ads", URL: "https://x.test/ads.txt"}},
		Rules: []engine.Rule{
			{Type: engine.RuleRuleSet, Value: "ads", Via: "REJECT"},
			{Type: engine.RuleMatch, Via: "DIRECT"},
		},
	}
	merged, warnings := Merge(user, map[string]*Snapshot{"air": snapshot})
	if len(warnings) != 0 {
		t.Fatalf("warnings %v", warnings)
	}
	if len(merged.Nodes) != 3 || merged.Nodes[1].Name != "HK (air 2)" || merged.Groups[0].Members[0] != "HK (air 2)" {
		t.Fatalf("collision handling: %+v / %+v", merged.Nodes, merged.Groups)
	}
	rules := merged.Rules
	if len(rules) != 4 || rules[2].Type != engine.RuleRuleSet || rules[3].Via != "Proxy" {
		t.Fatalf("user rules first, user's match last: %+v", rules)
	}
	core, err := engine.New(merged, nil)
	if err != nil || core == nil {
		t.Fatalf("merged config invalid: %v", err)
	}

	// Before the first download the rules pointing at the group are pruned.
	merged, warnings = Merge(user, nil)
	if merged.Selected != "DIRECT" || len(merged.Rules) != 1 || len(warnings) != 2 {
		t.Fatalf("prune: selected %s rules %+v warnings %v", merged.Selected, merged.Rules, warnings)
	}
}

func TestLoadFallsBackToLastGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := filepath.Join(dir, "cache")
	validate := func(c engine.Config) error { return engine.Validate(c, backend.Default()) }
	os.WriteFile(path, []byte(`{"mode":"global","selected":"DIRECT","nodes":[],"rules":[]}`), 0o600)
	if loaded, err := Load(path, data, validate); err != nil || loaded.Fallback || loaded.Merged.Mode != "global" {
		t.Fatalf("good load: %+v %v", loaded, err)
	}
	os.WriteFile(path, []byte(`{"mode":"global", broken`), 0o600)
	loaded, err := Load(path, data, validate)
	if err != nil || !loaded.Fallback || loaded.Merged.Mode != "global" || !strings.Contains(loaded.Warnings[0], "上一次可用") {
		t.Fatalf("fallback: %+v %v", loaded, err)
	}
	if _, err := Check(path, data, validate); err == nil {
		t.Fatal("Check must not fall back")
	}
	// A broken file must never overwrite the last good copy.
	if good, _ := os.ReadFile(filepath.Join(data, "last-good.json")); !strings.Contains(string(good), "global") {
		t.Fatalf("last good copy damaged: %s", good)
	}
}
