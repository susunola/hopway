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
	"syscall"
	"time"

	"mac-proxy/internal/backend"
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
	URL         string `json:"url,omitempty"`
	FallbackURL string `json:"fallbackUrl,omitempty"`
	Interval    int    `json:"intervalSec,omitempty"`
}

const (
	defaultProbeURL      = "https://www.gstatic.com/generate_204"
	defaultProbeFallback = "https://www.cloudflare.com/cdn-cgi/trace"
	defaultProbeInterval = 300
	defaultTolerance     = 50
	probeTimeout         = 6 * time.Second
	probeParallel        = 8
)

func validateProbeURL(target string) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("health target must be an HTTP or HTTPS URL with a host")
	}
	return nil
}

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
	Inconclusive bool   `json:"inconclusive,omitempty"`
	Target       string `json:"target,omitempty"`
	CheckedAt    int64  `json:"checkedAt,omitempty"`
	started      time.Time
	finished     time.Time
}

func (engine *Engine) ProbeResults(ctx context.Context, names []string, emit func(ProbeResult) error) error {
	return engine.probeNodes(ctx, names, emit)
}

func (engine *Engine) probeNodes(ctx context.Context, names []string, emit func(ProbeResult) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	engine.mu.Lock()
	network := engine.networkCtx
	epoch := engine.networkEpoch.Load()
	engine.mu.Unlock()
	if network != nil {
		stop := context.AfterFunc(network, cancel)
		defer stop()
	}
	if names == nil {
		for name := range engine.dialers {
			names = append(names, name)
		}
	}
	workers := min(probeParallel, len(names))
	work := make(chan string)
	results := make(chan ProbeResult, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for name := range work {
				result := engine.probe(ctx, name)
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(work)
		for _, name := range names {
			select {
			case work <- name:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wait.Wait()
		close(results)
	}()

	var emitErr error
	deliver := func(result ProbeResult) {
		if !engine.saveProbe(ctx, epoch, &result) {
			return
		}
		if emit != nil {
			if emitErr = emit(result); emitErr != nil {
				cancel()
			}
		}
	}
	var failures []ProbeResult
	passed := false
	for result := range results {
		// Until at least one node reaches a target, a group of dial
		// failures may be a network outage. Publish successes immediately.
		if len(names) > 1 && !passed && result.Failure != "" && !result.Inconclusive {
			failures = append(failures, result)
			continue
		}
		deliver(result)
		if !passed && result.Failure == "" {
			passed = true
			for _, failed := range failures {
				deliver(failed)
			}
			failures = nil
		}
	}
	for _, failed := range failures {
		failed.Inconclusive = true
		deliver(failed)
	}
	if emitErr != nil {
		return emitErr
	}
	if engine.networkEpoch.Load() != epoch {
		return context.Canceled
	}
	return ctx.Err()
}

func (engine *Engine) saveProbe(ctx context.Context, epoch uint64, result *ProbeResult) bool {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if ctx.Err() != nil || engine.networkEpoch.Load() != epoch {
		return false
	}
	previous := engine.health[result.Name]
	checked := result.finished
	if previous != nil && (previous.checked.After(checked) ||
		(result.Failure != "" && previous.succeeded.After(result.started))) {
		result.Inconclusive = true
	}
	if !result.Inconclusive {
		h := &nodeHealth{latency: time.Duration(result.Milliseconds) * time.Millisecond,
			alive: result.Failure == "", err: result.Failure, checked: checked}
		if previous != nil {
			h.succeeded = previous.succeeded
		}
		engine.health[result.Name] = h
	}
	return true
}

func (engine *Engine) probe(ctx context.Context, name string) ProbeResult {
	start := time.Now()
	result := ProbeResult{Name: name, started: start}
	dialer := engine.dialers[name]
	if dialer == nil {
		result.Failure, result.CheckedAt = "unknown node", start.UnixMilli()
		result.finished = start
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	primary := ctx
	if engine.probeFallback != "" {
		var stop context.CancelFunc
		primary, stop = context.WithTimeout(ctx, 4*time.Second)
		defer stop()
	}
	target := engine.probeURL
	latency, err := probeTarget(primary, dialer, target)
	var primaryErr error
	if err != nil && ctx.Err() == nil && engine.probeFallback != "" {
		primaryErr = err
		target = engine.probeFallback
		latency, err = probeTarget(ctx, dialer, target)
	}
	if parsed, parseErr := url.Parse(target); parseErr == nil {
		result.Target = parsed.Hostname()
	}
	result.finished = time.Now()
	result.CheckedAt = result.finished.UnixMilli()
	if err == nil {
		result.Milliseconds = max(latency.Milliseconds(), 1)
		return result
	}
	result.Failure = err.Error()
	result.Inconclusive = inconclusiveProbe(err) || inconclusiveProbe(primaryErr)
	return result
}

type probeHTTPStatus int

func (status probeHTTPStatus) Error() string { return fmt.Sprintf("probe returned HTTP %d", status) }

func inconclusiveProbe(err error) bool {
	var status probeHTTPStatus
	return errors.As(err, &status) || errors.Is(err, syscall.ENETDOWN) || errors.Is(err, syscall.ENETUNREACH)
}

func probeTarget(ctx context.Context, dialer backend.Dialer, target string) (time.Duration, error) {
	transport := &http.Transport{
		// Each transport handles one probe. Bind its dial to the request
		// because the HTTP transport can otherwise keep the dial alive.
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, address)
		},
		DisableKeepAlives: true, TLSHandshakeTimeout: probeTimeout, ResponseHeaderTimeout: probeTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
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
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return 0, probeHTTPStatus(response.StatusCode)
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
