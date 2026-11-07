package engine

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/ruleset"
)

func TestRuleSetMatching(t *testing.T) {
	set := ruleset.NewSet("s")
	content, _ := ruleset.Parse(ruleset.FormatText, ruleset.BehaviorClassical,
		[]byte("DOMAIN-SUFFIX,listed.test\nIP-CIDR,198.51.100.0/24\n"))
	set.Store(content)
	rules := []Rule{
		{Type: RuleDomain, Value: "first.listed.test", Via: "A"},
		{Type: RuleRuleSet, Value: "s", Via: "B"},
		{Type: RuleMatch, Via: "C"},
	}
	m, err := newMatcher(rules, func(string) bool { return true }, map[string]*ruleset.Set{"s": set})
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
	m, _ = newMatcher(rules, func(string) bool { return true }, map[string]*ruleset.Set{"s": set})
	if got := rules[m.match("via-ip.test", resolve, nil)].Via; got != "C" {
		t.Errorf("no-resolve rule set matched a resolved name: %s", got)
	}
	if _, err := newMatcher([]Rule{{Type: RuleRuleSet, Value: "missing", Via: "A"}}, func(string) bool { return true }, nil); err == nil {
		t.Error("accepted a rule referring to an unknown rule set")
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
		name, _ := core.route(host, core.policy, nil)
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
