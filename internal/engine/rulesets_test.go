package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/ruleset"
)

func TestRuleSetRequestsKeepSnapshotAcrossDNS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.list")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("IP-CIDR,192.0.2.0/24\n")
	config := Default()
	config.RuleSets = []RuleSet{{Name: "mixed", Path: path}}
	config.Rules = []Rule{{Type: RuleRuleSet, Value: "mixed", Via: "REJECT"}, {Type: RuleMatch, Via: "DIRECT"}}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	// Both versions reject sample.test. Mixing the old domain evaluation
	// with the new IP index would fall through to DIRECT.
	const requests = 256
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{}, requests)
	decisions := make(chan int, requests)
	release := make(chan struct{})
	var workers sync.WaitGroup
	defer workers.Wait()
	defer func() {
		if release != nil {
			close(release)
		}
	}()
	blocked := release
	address := []netip.Addr{netip.MustParseAddr("192.0.2.12")}
	for range requests {
		workers.Go(func() {
			decisions <- core.rules.match("sample.test", func(string) []netip.Addr {
				entered <- struct{}{}
				<-blocked
				return address
			}, nil)
		})
	}
	for range requests {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("routes did not reach DNS")
		}
	}
	write("DOMAIN,sample.test\n")
	if result := core.RefreshRuleSets(ctx, true); result.Succeeded != 1 || result.Canceled {
		t.Fatalf("rule-set refresh: %+v", result)
	}
	if index := core.rules.match("sample.test", nil, nil); index != 0 {
		t.Fatalf("new request did not see updated domain index: %d", index)
	}
	close(release)
	release = nil
	for range requests {
		if index := <-decisions; index != 0 {
			t.Fatalf("in-flight request mixed rule-set generations: %d", index)
		}
	}
}

func TestRuleSetIndexesReuseOnlyMatchingContent(t *testing.T) {
	config := Default()
	for _, name := range []string{"alpha", "beta"} {
		path := filepath.Join(t.TempDir(), name+".list")
		if err := os.WriteFile(path, []byte(fmt.Sprintf("DOMAIN,%s.test\n", name)), 0o600); err != nil {
			t.Fatal(err)
		}
		config.RuleSets = append(config.RuleSets, RuleSet{Name: name, Path: path})
	}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	first, second := core.ruleSets[0].content, core.ruleSets[1].content
	snapshot := core.rules.snapshot.Load()
	ctx := context.Background()
	if result := core.RefreshRuleSets(ctx, true); result.Succeeded != 2 || core.rules.snapshot.Load() != snapshot {
		t.Fatalf("identical contents changed the snapshot: %+v", result)
	}
	if err := os.WriteFile(config.RuleSets[0].Path, []byte("DOMAIN,new.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := core.RefreshRuleSets(ctx, true); result.Succeeded != 2 {
		t.Fatalf("refresh: %+v", result)
	}
	latest := core.rules.snapshot.Load()
	if latest == snapshot || (*latest)[0] == first || (*latest)[1] != second ||
		!(*snapshot)[0].MatchDomain("alpha.test") || !(*latest)[0].MatchDomain("new.test") {
		t.Fatal("refresh must replace the changed index and preserve the unchanged index")
	}
	reloaded, err := NewContext(ctx, config, nil, nil, core.RuleSetIndexes())
	if err != nil {
		t.Fatal(err)
	}
	for slot, state := range reloaded.ruleSets {
		if state.content != (*latest)[slot] {
			t.Fatalf("unchanged digest rebuilt rule set %q", state.Name)
		}
	}
	config.RuleSets[0].Behavior = ruleset.BehaviorDomain
	reloaded, err = NewContext(ctx, config, nil, nil, core.RuleSetIndexes())
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ruleSets[0].content == (*latest)[0] || reloaded.ruleSets[1].content != second {
		t.Fatal("digest reuse must respect parser behavior")
	}
}

func TestRuleSetMatching(t *testing.T) {
	content, _ := ruleset.Parse(ruleset.FormatText, ruleset.BehaviorClassical,
		[]byte("DOMAIN-SUFFIX,listed.test\nIP-CIDR,198.51.100.0/24\n"))
	sets := []*ruleSetState{{RuleSet: RuleSet{Name: "s"}, content: content}}
	rules := []Rule{
		{Type: RuleDomain, Value: "first.listed.test", Via: "A"},
		{Type: RuleRuleSet, Value: "s", Via: "B"},
		{Type: RuleMatch, Via: "C"},
	}
	m, err := newMatcher(rules, func(string) bool { return true }, sets)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(host string) []netip.Addr {
		if host == "via-ip.test" {
			return []netip.Addr{netip.MustParseAddr("198.51.100.7")}
		}
		return nil
	}
	for host, want := range map[string]string{"first.listed.test": "A", "x.listed.test": "B", "198.51.100.1": "B",
		"via-ip.test": "B", "other.test": "C"} {
		if got := rules[m.match(host, resolve, nil)].Via; got != want {
			t.Errorf("%s: got %s want %s", host, got, want)
		}
	}
	rules[1].NoResolve = true
	m, _ = newMatcher(rules, func(string) bool { return true }, sets)
	if got := rules[m.match("via-ip.test", resolve, nil)].Via; got != "C" {
		t.Errorf("no-resolve rule set matched a resolved name: %s", got)
	}
	if _, err := newMatcher([]Rule{{Type: RuleRuleSet, Value: "missing", Via: "A"}}, func(string) bool { return true }, nil); err == nil {
		t.Error("accepted a rule referring to an unknown rule set")
	}
}

func TestConfiguredRuleSetRefreshRespectsSourceOverride(t *testing.T) {
	var defaultHits, overrideHits atomic.Int32
	const content = "payload:\n  - '+.blocked.test'\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/default.yaml" {
			defaultHits.Add(1)
		} else {
			overrideHits.Add(1)
		}
		_, _ = w.Write([]byte(content))
	}))
	defer server.Close()
	config := Default()
	config.RuleSetRefreshMin = 10
	config.DataDir = t.TempDir()
	config.RuleSets = []RuleSet{
		{Name: "default", URL: server.URL + "/default.yaml", Behavior: ruleset.BehaviorDomain},
		{Name: "override", URL: server.URL + "/override.yaml", Behavior: ruleset.BehaviorDomain, Interval: 1200},
	}
	validation, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range validation.ruleSets {
		path := validation.cachePath(set)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		cached := time.Now().Add(-15 * time.Minute)
		if err := os.Chtimes(path, cached, cached); err != nil {
			t.Fatal(err)
		}
	}
	core, err := New(config, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	core.RefreshRuleSets(context.Background(), false)
	if d, o := defaultHits.Load(), overrideHits.Load(); d != 1 || o != 0 {
		t.Fatalf("15-minute cache with 10- and 20-minute intervals: downloads %d and %d", d, o)
	}
}

func TestRemoteRuleSetCacheAndRefresh(t *testing.T) {
	var body atomic.Value
	body.Store("payload:\n  - '+.blocked.test'\n")
	var hits atomic.Int32
	var hold atomic.Bool
	started, canceled := make(chan struct{}), make(chan struct{})
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if hold.CompareAndSwap(true, false) {
			close(started)
			<-r.Context().Done()
			close(canceled)
			return
		}
		if body.Load().(string) == "" {
			http.Error(w, "gone", http.StatusBadGateway)
			return
		}
		w.Write([]byte(body.Load().(string)))
	})}
	go server.Serve(listener)
	defer server.Close()

	config := Default()
	config.DataDir = t.TempDir()
	config.RuleSets = []RuleSet{{Name: "ads", URL: "http://" + listener.Addr().String() + "/ads.yaml", Behavior: ruleset.BehaviorDomain}}
	config.Rules = []Rule{{Type: RuleRuleSet, Value: "ads", Via: "REJECT"}, {Type: RuleMatch, Via: "DIRECT"}}
	open := func() *Engine {
		core, err := New(config, backend.Default())
		if err != nil {
			t.Fatal(err)
		}
		return core
	}
	via := func(core *Engine, host string) string {
		name, _, _ := core.route(context.Background(), host, core.policy, nil)
		return name
	}

	core := open()
	core.RefreshRuleSets(context.Background(), false) // what the background loop does first
	if via(core, "a.blocked.test") != "REJECT" {
		t.Fatalf("downloaded set not applied: %+v", core.Status().RuleSets)
	}
	status := core.Status().RuleSets[0]
	if status.Entries != 1 || status.Updated == 0 || status.Error != "" {
		t.Fatalf("status %+v", status)
	}
	core.Close()

	// The source goes away: a restart still has the cached copy, and a failed
	// refresh keeps serving it.
	body.Store("")
	core = open()
	defer core.Close()
	if via(core, "a.blocked.test") != "REJECT" {
		t.Fatal("cached rule set not loaded at start")
	}
	core.RefreshRuleSets(context.Background(), true)
	status = core.Status().RuleSets[0]
	if via(core, "a.blocked.test") != "REJECT" || status.Error == "" {
		t.Fatalf("failed refresh must keep the old copy and report the error: %+v", status)
	}
	cachePath := core.cachePath(core.ruleSets[0])
	previous, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	body.Store("payload: [")
	core.RefreshRuleSets(context.Background(), true)
	status = core.Status().RuleSets[0]
	if after, err := os.ReadFile(cachePath); err != nil || !bytes.Equal(after, previous) ||
		via(core, "a.blocked.test") != "REJECT" || status.Error == "" {
		t.Fatalf("malformed response replaced the cached rule set or was not reported: %+v", status)
	}

	// A new list replaces the old one in place.
	body.Store("payload:\n  - '+.other.test'\n")
	core.RefreshRuleSets(context.Background(), true)
	if via(core, "a.blocked.test") != "DIRECT" || via(core, "x.other.test") != "REJECT" {
		t.Fatal("refreshed content not swapped in")
	}

	// A slow download started on the old network is canceled and is not
	// reported as a provider failure or applied to the active matcher.
	good := core.Status().RuleSets[0]
	hold.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		core.RefreshRuleSets(ctx, true)
	}()
	wait := func(event <-chan struct{}, message string) {
		t.Helper()
		select {
		case <-event:
		case <-ctx.Done():
			t.Fatal(message)
		}
	}
	wait(started, "rule set download did not reach the server")
	core.NetworkChanged()
	wait(canceled, "rule set HTTP request survived network change")
	wait(finished, "old rule set refresh did not exit")
	if got := core.Status().RuleSets[0]; got != good || via(core, "x.other.test") != "REJECT" {
		t.Fatalf("canceled refresh changed last good rule set: %+v", got)
	}
	body.Store("payload:\n  - '+.new.test'\n")
	core.RefreshRuleSets(ctx, true)
	if via(core, "x.new.test") != "REJECT" || via(core, "x.other.test") != "DIRECT" {
		t.Fatal("rule set did not refresh on the new network")
	}
}
