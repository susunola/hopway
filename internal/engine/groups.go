package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"sync"
	"time"
)

// Group types.
const (
	GroupSelect   = "select"   // the user picks a member
	GroupURLTest  = "url-test" // lowest measured latency, with hysteresis
	GroupFallback = "fallback" // first healthy member in order
)

type Group struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Members   []string `json:"members"`
	Selected  string   `json:"selected,omitempty"`
	Tolerance int      `json:"toleranceMs,omitempty"`
}

// Health configures latency probing for url-test and fallback groups.
type Health struct {
	URL      string `json:"url,omitempty"`
	Interval int    `json:"intervalSec,omitempty"`
}

const (
	defaultProbeURL      = "https://www.gstatic.com/generate_204"
	defaultProbeInterval = 300
	defaultTolerance     = 50
	probeTimeout         = 6 * time.Second
	probeParallel        = 8
)

type nodeHealth struct {
	latency   time.Duration
	alive     bool
	checked   time.Time
	err       string
	succeeded time.Time // last real connection that worked through the node
}

type group struct {
	Group
	current string // url-test: member currently preferred, kept until clearly beaten
}

type choice struct {
	route []string // groups passed through, outermost first
	via   string   // node, DIRECT or REJECT
}

func validateGroups(groups []Group, known func(string) bool) (map[string]*group, error) {
	result := make(map[string]*group, len(groups))
	for _, g := range groups {
		if g.Name == "" || known(g.Name) || result[g.Name] != nil || (g.Name == "SELECT" || g.Name == "AUTO") {
			return nil, fmt.Errorf("invalid or duplicate group name %q", g.Name)
		}
		switch g.Type {
		case GroupSelect, GroupURLTest, GroupFallback:
		default:
			return nil, fmt.Errorf("group %q has unknown type %q", g.Name, g.Type)
		}
		if len(g.Members) == 0 {
			return nil, fmt.Errorf("group %q has no members", g.Name)
		}
		if g.Tolerance < 0 {
			return nil, fmt.Errorf("group %q has a negative tolerance", g.Name)
		}
		result[g.Name] = &group{Group: g}
	}
	for _, g := range result {
		seen := map[string]bool{}
		for _, member := range g.Members {
			if !known(member) && result[member] == nil {
				return nil, fmt.Errorf("group %q refers to unknown member %q", g.Name, member)
			}
			if seen[member] {
				return nil, fmt.Errorf("group %q lists %q twice", g.Name, member)
			}
			seen[member] = true
		}
		if g.Type == GroupSelect {
			if g.Selected == "" {
				g.Selected = g.Members[0]
			} else if !seen[g.Selected] {
				return nil, fmt.Errorf("group %q selects %q, which is not a member", g.Name, g.Selected)
			}
		}
	}
	// Reject cycles: a group may not contain itself through any path.
	state := map[string]int{}
	var visit func(string) error
	visit = func(name string) error {
		g := result[name]
		if g == nil {
			return nil
		}
		switch state[name] {
		case 1:
			return fmt.Errorf("group %q is part of a cycle", name)
		case 2:
			return nil
		}
		state[name] = 1
		for _, member := range g.Members {
			if err := visit(member); err != nil {
				return err
			}
		}
		state[name] = 2
		return nil
	}
	for name := range result {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// choices expands an outbound name into ordered dial candidates. Caller holds engine.mu.
func (engine *Engine) choices(name string) []choice {
	if name == "AUTO" {
		if engine.auto == nil || len(engine.auto.orderedCandidates) == 0 {
			return []choice{{via: "REJECT"}}
		}
		list := make([]choice, 0, len(engine.auto.orderedCandidates))
		for _, name := range engine.auto.orderedCandidates {
			list = append(list, choice{via: name})
		}
		return list
	}
	g := engine.groups[name]
	if g == nil {
		return []choice{{via: name}}
	}
	prefix := func(list []choice) []choice {
		for i := range list {
			list[i].route = append([]string{g.Name}, list[i].route...)
		}
		return list
	}
	if g.Type == GroupSelect {
		return prefix(engine.choices(g.Selected))
	}
	type ranked struct {
		member  string
		options []choice
		alive   bool
		known   bool
		latency time.Duration
	}
	members := make([]ranked, 0, len(g.Members))
	for _, member := range g.Members {
		options := engine.choices(member)
		r := ranked{member: member, options: options, alive: true}
		if len(options) != 0 {
			if h := engine.health[options[0].via]; h != nil && !h.checked.IsZero() {
				r.alive, r.known, r.latency = h.alive, true, h.latency
			}
			if options[0].via == "REJECT" {
				r.alive = false
			}
		}
		members = append(members, r)
	}
	if g.Type == GroupURLTest {
		sort.SliceStable(members, func(i, j int) bool {
			a, b := members[i], members[j]
			if a.alive != b.alive {
				return a.alive
			}
			if a.known != b.known {
				return a.known
			}
			return a.latency < b.latency
		})
		tolerance := time.Duration(g.Tolerance) * time.Millisecond
		if g.Tolerance == 0 {
			tolerance = defaultTolerance * time.Millisecond
		}
		for i, m := range members {
			if m.member == g.current && m.alive && i > 0 && members[0].known && m.known &&
				m.latency <= members[0].latency+tolerance {
				members = append([]ranked{m}, append(members[:i:i], members[i+1:]...)...)
				break
			}
		}
		if len(members) != 0 && members[0].alive {
			g.current = members[0].member
		}
	} else {
		sort.SliceStable(members, func(i, j int) bool { return members[i].alive && !members[j].alive })
	}
	var list []choice
	for _, m := range members {
		list = append(list, m.options...)
	}
	return prefix(list)
}

// autoMembers lists nodes reachable from url-test and fallback groups.
func (engine *Engine) autoMembers() []string {
	seen := map[string]bool{}
	var walk func(string, bool)
	walk = func(name string, auto bool) {
		if g := engine.groups[name]; g != nil {
			for _, member := range g.Members {
				walk(member, auto || g.Type != GroupSelect)
			}
			return
		}
		if auto && engine.dialers[name] != nil {
			seen[name] = true
		}
	}
	for name := range engine.groups {
		walk(name, false)
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (engine *Engine) healthLoop(ctx context.Context, interval time.Duration) {
	engine.Probe(ctx, engine.autoMembers())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			engine.Probe(ctx, engine.autoMembers())
		}
	}
}

// Probe measures names (all nodes if empty) concurrently and records results.
func (engine *Engine) Probe(ctx context.Context, names []string) {
	_ = engine.probeNodes(ctx, names, nil)
}

type ProbeResult struct {
	Name         string `json:"name"`
	Milliseconds int64  `json:"milliseconds,omitempty"`
	Failure      string `json:"failure,omitempty"`
}

func (engine *Engine) ProbeResults(ctx context.Context, names []string, emit func(ProbeResult) error) error {
	return engine.probeNodes(ctx, names, emit)
}

func (engine *Engine) probeNodes(ctx context.Context, names []string, emit func(ProbeResult) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if engine.ctx != nil {
		stop := context.AfterFunc(engine.ctx, cancel)
		defer stop()
	}
	var emitMu sync.Mutex
	var emitErr error
	if names == nil {
		for name := range engine.dialers {
			names = append(names, name)
		}
	}
	work := make(chan string)
	var wait sync.WaitGroup
	for range min(probeParallel, len(names)) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for name := range work {
				started := time.Now()
				latency, err := engine.probe(ctx, name)
				engine.mu.Lock()
				previous := engine.health[name]
				h := &nodeHealth{latency: latency, alive: err == nil, checked: time.Now()}
				if previous != nil {
					h.succeeded = previous.succeeded
				}
				if err != nil {
					h.err = err.Error()
					// A probe that fails (the probe URL may be blocked) does
					// not outweigh real traffic that worked meanwhile.
					if h.succeeded.After(started) {
						h.alive, h.latency, h.err = true, previous.latency, ""
					}
				}
				if ctx.Err() == nil {
					engine.health[name] = h
				}
				engine.mu.Unlock()
				if emit != nil && ctx.Err() == nil {
					result := ProbeResult{Name: name, Failure: h.err}
					if h.alive {
						result.Milliseconds = max(h.latency.Milliseconds(), 1)
					}
					emitMu.Lock()
					if emitErr == nil {
						emitErr = emit(result)
						if emitErr != nil {
							cancel()
						}
					}
					emitMu.Unlock()
				}
			}
		}()
	}
schedule:
	for _, name := range names {
		select {
		case work <- name:
		case <-ctx.Done():
			break schedule
		}
	}
	close(work)
	wait.Wait()
	if emitErr != nil {
		return emitErr
	}
	return ctx.Err()
}

func (engine *Engine) probe(ctx context.Context, name string) (time.Duration, error) {
	dialer := engine.dialers[name]
	if dialer == nil {
		return 0, errors.New("unknown node")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, address)
		},
		DisableKeepAlives: true, TLSHandshakeTimeout: probeTimeout, ResponseHeaderTimeout: probeTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, engine.probeURL, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return 0, err
	}
	response.Body.Close()
	if response.StatusCode >= 500 {
		return 0, fmt.Errorf("probe returned HTTP %d", response.StatusCode)
	}
	return time.Since(start), nil
}

// SelectInGroup changes the member a select group uses.
func (engine *Engine) SelectInGroup(name, member string) error {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	g := engine.groups[name]
	if g == nil {
		return errors.New("group does not exist")
	}
	if g.Type != GroupSelect {
		return errors.New("only select groups can be switched by hand")
	}
	for _, m := range g.Members {
		if m == member {
			g.Selected = member
			return nil
		}
	}
	return errors.New("not a member of this group")
}

// Runtime is the state a user changes while HopWay runs, carried across reloads.
type Runtime struct {
	Policy     Policy
	Selections map[string]string // select group -> member
}

func (engine *Engine) Runtime() Runtime {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	runtime := Runtime{Policy: engine.policy, Selections: map[string]string{}}
	for name, g := range engine.groups {
		if g.Type == GroupSelect {
			runtime.Selections[name] = g.Selected
		}
	}
	return runtime
}

// Restore applies what still makes sense of a previous engine's runtime state.
func (engine *Engine) Restore(runtime Runtime) {
	for name, member := range runtime.Selections {
		engine.SelectInGroup(name, member)
	}
	if runtime.Policy.Mode == "auto" && runtime.Policy.Auto != nil {
		config := *runtime.Policy.Auto
		config.Groups = nil
		for _, group := range runtime.Policy.Auto.Groups {
			saved := group.Nodes
			group.Nodes = nil
			var providerNodes []string
			if group.ProviderID != "" {
				for _, sub := range engine.subscriptions {
					if sub.Key() == group.ProviderID && !sub.Paused {
						providerNodes = sub.Nodes
						if sub.Alias != "" {
							group.Name = sub.Alias
						} else {
							group.Name = sub.Name
						}
						break
					}
				}
			}
			for _, name := range saved {
				if engine.types[name] != "" && (group.ProviderID == "" || slices.Contains(providerNodes, name)) {
					group.Nodes = append(group.Nodes, name)
				}
			}
			if len(group.Nodes) != 0 {
				config.Groups = append(config.Groups, group)
			}
		}
		if len(config.Groups) == 0 {
			_ = engine.SetPolicy(Policy{Mode: "global", Selected: "REJECT"})
			return
		}
		runtime.Policy.Auto = &config
	}
	if err := engine.SetPolicy(runtime.Policy); err != nil && runtime.Policy.Mode == "auto" {
		_ = engine.SetPolicy(Policy{Mode: "global", Selected: "REJECT"})
	}
}

// Active reports open connections.
func (engine *Engine) Active() int {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return len(engine.live) + len(engine.livePackets)
}
