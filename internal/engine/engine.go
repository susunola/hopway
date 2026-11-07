package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/lifetime"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/peer"
	"mac-proxy/internal/process"
	"mac-proxy/internal/trace"
	"mac-proxy/internal/wire"
)

const ConfigVersion = 1

type Config struct {
	Version   int             `json:"version,omitempty"`
	SOCKSPort int             `json:"socksPort"`
	HTTPPort  int             `json:"httpPort"`
	Mode      string          `json:"mode"`
	Selected  string          `json:"selected"`
	Nodes     []outbound.Node `json:"nodes"`
	Groups    []Group         `json:"groups,omitempty"`
	Rules     []Rule          `json:"rules"`
	RuleSets  []RuleSet       `json:"ruleSets,omitempty"`
	Health    *Health         `json:"health,omitempty"`
	// Subscriptions are merged in by the profile package; the engine only
	// sees their nodes, groups and rules.
	Subscriptions          []Subscription `json:"subscriptions,omitempty"`
	SubscriptionNodes      []string       `json:"subscriptionNodes,omitempty"` // inline nodes from older versions
	SubscriptionRefreshMin int            `json:"subscriptionRefreshMin,omitempty"`
	RuleSetRefreshMin      int            `json:"ruleSetRefreshMin,omitempty"`
	// SystemProxy points macOS's proxy settings at HopWay while it runs.
	SystemProxy bool `json:"systemProxy,omitempty"`
	// TUN captures all traffic through a virtual network device.
	TUN               *TUNConfig              `json:"tun,omitempty"`
	MaxDialAttempts   int                     `json:"maxDialAttempts,omitempty"`
	Performance       PerformanceConfig       `json:"performance,omitzero"`
	Resources         ResourceLimits          `json:"resources,omitzero"`
	ConnectionHistory ConnectionHistoryConfig `json:"connectionHistory,omitzero"`

	// DataDir holds caches (downloaded rule sets). Set by the caller, not saved.
	DataDir string `json:"-"`
}

type TUNConfig struct {
	Enabled bool   `json:"enabled"`
	MTU     uint32 `json:"mtu,omitempty"`
	IPv6    bool   `json:"ipv6,omitempty"` // capture IPv6 too (fake IPv6 answers, ::/0 route)
}

// Subscription is a remote node list refreshed in the background.
type Subscription struct {
	Name         string             `json:"name"`
	ID           string             `json:"id,omitempty"`
	SnapshotKey  string             `json:"snapshotKey,omitempty"`
	Alias        string             `json:"alias,omitempty"`
	Paused       bool               `json:"paused,omitempty"`
	Agent        string             `json:"agent,omitempty"`
	Usage        *SubscriptionUsage `json:"usage,omitempty"`
	UsageSamples []UsageSample      `json:"usageSamples,omitempty"`
	Nodes        []string           `json:"nodes,omitempty"`
	URL          string             `json:"url"`
	Interval     int                `json:"intervalSec,omitempty"` // default 6 hours
}

func Default() Config {
	return Config{SOCKSPort: 1080, HTTPPort: 8080, Mode: "rule", Selected: "DIRECT"}
}

func Decode(reader io.Reader) (Config, error) {
	defaults := Default()
	config := &defaults
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	if config == nil || decoder.Decode(new(any)) != io.EOF {
		return Config{}, errors.New("expected one JSON configuration object")
	}
	if config.Version < 0 || config.Version > ConfigVersion {
		return Config{}, fmt.Errorf("unsupported configuration version %d", config.Version)
	}
	config.Version = ConfigVersion
	return *config, nil
}

type Policy struct {
	Auto     *AutoConfig `json:"auto,omitempty"`
	Mode     string      `json:"mode"`
	Selected string      `json:"selected"`
}

type NodeSummary struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	LatencyMs    int64  `json:"latencyMs,omitempty"`
	Alive        *bool  `json:"alive,omitempty"`
	Error        string `json:"error,omitempty"`
	HealthAt     int64  `json:"healthAt,omitempty"`
	FailureStage string `json:"failureStage,omitempty"`
	FailureCode  string `json:"failureCode,omitempty"`
	ProbeTarget  string `json:"probeTarget,omitempty"`
}

type GroupStatus struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Members  []string `json:"members"`
	Now      string   `json:"now"`                // node currently used
	Selected string   `json:"selected,omitempty"` // select groups: the member chosen
}

// Record describes one connection. Timings are milliseconds.
type Record struct {
	ID              uint64        `json:"id"`
	Start           int64         `json:"start"`
	Inbound         string        `json:"inbound"`
	Target          string        `json:"target"`
	Via             string        `json:"via"`
	Route           []string      `json:"route,omitempty"`
	Rule            string        `json:"rule"`
	State           string        `json:"state"`
	Sent            uint64        `json:"sent"`
	Recv            uint64        `json:"received"`
	Error           string        `json:"error,omitempty"`
	Stage           string        `json:"stage,omitempty"`
	FailureCode     string        `json:"failureCode,omitempty"`
	Failures        []DialFailure `json:"failures,omitempty"`
	Server          string        `json:"server,omitempty"`
	Shared          bool          `json:"shared,omitempty"`      // rode a multiplexed session, no socket of its own
	Network         string        `json:"network,omitempty"`     // "udp" for datagram sessions
	Process         string        `json:"process,omitempty"`     // app or executable name
	ProcessPath     string        `json:"processPath,omitempty"` // executable path
	ProcessBundleID string        `json:"processBundleId,omitempty"`
	PID             uint32        `json:"pid,omitempty"`
	Attempts        int           `json:"attempts,omitempty"`
	DNSMs           int64         `json:"dnsMs,omitempty"`
	ConnectMs       int64         `json:"connectMs,omitempty"`
	HandshakeMs     int64         `json:"handshakeMs,omitempty"`
	FirstByteMs     int64         `json:"firstByteMs,omitempty"`
}

type Status struct {
	Auto           *AutoStatus                   `json:"auto,omitempty"`
	Backend        string                        `json:"backend"`
	Policy         Policy                        `json:"policy"`
	Nodes          []NodeSummary                 `json:"nodes"`
	Groups         []GroupStatus                 `json:"groups,omitempty"`
	RuleSets       []RuleSetStatus               `json:"ruleSets,omitempty"`
	Connections    []Record                      `json:"connections,omitzero"`
	Active         int                           `json:"active"`
	SessionTraffic *trafficCount                 `json:"sessionTraffic,omitempty"`
	UDPDrops       map[string]wire.UDPDropCounts `json:"udpDrops,omitempty"`
	Resources      *ResourceStatus               `json:"resources,omitempty"`
	RuleDefaults   RuleDefaults                  `json:"ruleDefaults"`
}

type RuleDefaults struct {
	ExplicitMatch uint64 `json:"explicitMatch"`
	Implicit      uint64 `json:"implicit"`
}

type Engine struct {
	auto          *autoState
	autoWake      chan struct{}
	subscriptions []Subscription
	traffic       *TrafficLedger
	mu            sync.Mutex
	policy        Policy
	backend       string
	instance      backend.Instance
	dialers       map[string]backend.Dialer
	dialSlots     map[string]*endpointSlots
	types         map[string]string
	servers       map[string]string
	order         []string
	groups        map[string]*group
	health        map[string]*nodeHealth
	rules         *matcher
	attempts      int
	performance   performanceLimits
	probeURL      string
	probeFallback string
	sequence      uint64
	live          map[uint64]*tracked
	livePackets   map[uint64]*trackedPacket
	peakTCP       int
	peakUDP       int
	budget        *ResourceBudget
	recent        recentRecords
	recentLimit   int
	recentTimer   *time.Timer
	recentTTL     time.Duration
	journal       connectionJournal
	ports         map[uint16]bool
	ctx           context.Context
	work          *lifetime.Group
	networkCtx    context.Context
	cancelNetwork context.CancelFunc
	networkEpoch  atomic.Uint64
	ruleRefresh   chan struct{}
	closed        bool
	closeOnce     sync.Once
	closeErr      error

	lookupProcess    func(client, server netip.AddrPort) (*process.Owner, error)
	lookupProcessUDP func(client, server netip.AddrPort) (*process.Owner, error)
	dataDir          string
	ruleSets         []*ruleSetState
	ruleSetCost      uint64
	explicitMatch    atomic.Uint64
	implicitDefault  atomic.Uint64
}

const (
	defaultDialAttempts    = 3
	maxAllowedDialAttempts = 8
	endpointDialLimit      = 64
)

// New builds an engine; localPorts are HopWay's own listeners, which no
// connection may be sent back to.
func New(config Config, impl backend.Backend, localPorts ...int) (*Engine, error) {
	return NewWithResourceBudget(config, impl, nil, localPorts...)
}

// NewWithResourceBudget shares opening and UDP limits across engine reloads.
func NewWithResourceBudget(config Config, impl backend.Backend, budget *ResourceBudget, localPorts ...int) (*Engine, error) {
	return NewContext(context.Background(), config, impl, budget, nil, localPorts...)
}

// NewContext builds a proxy with cancellable rule-set loading. A caller
// building a replacement can provide indexes from the running proxy.
func NewContext(ctx context.Context, config Config, impl backend.Backend, budget *ResourceBudget, indexes RuleSetIndexes, localPorts ...int) (*Engine, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if config.SOCKSPort < 0 || config.SOCKSPort > 65535 || config.HTTPPort < 0 || config.HTTPPort > 65535 ||
		(config.SOCKSPort != 0 && config.SOCKSPort == config.HTTPPort) {
		return nil, errors.New("proxy ports must be distinct or 0 for automatic assignment")
	}
	if config.TUN != nil {
		if err := wire.ValidateTUNMTU(config.TUN.MTU, config.TUN.IPv6); err != nil {
			return nil, err
		}
	}
	if config.MaxDialAttempts < 0 || config.MaxDialAttempts > maxAllowedDialAttempts {
		return nil, fmt.Errorf("maxDialAttempts must be between 0 and %d", maxAllowedDialAttempts)
	}
	attempts := config.MaxDialAttempts
	if attempts == 0 {
		attempts = defaultDialAttempts
	}
	performance, err := config.Performance.limits()
	if err != nil {
		return nil, err
	}
	resources, err := config.Resources.effective()
	if err != nil {
		return nil, err
	}
	recentLimit, recentTTL, err := config.ConnectionHistory.limits()
	if err != nil {
		return nil, err
	}
	engine := &Engine{subscriptions: config.Subscriptions, autoWake: make(chan struct{}, 1), dialers: make(map[string]backend.Dialer), types: map[string]string{"DIRECT": "direct", "REJECT": "reject"}, servers: map[string]string{},
		order: []string{"DIRECT", "REJECT"}, health: make(map[string]*nodeHealth),
		live: make(map[uint64]*tracked), livePackets: make(map[uint64]*trackedPacket), ports: make(map[uint16]bool), probeURL: defaultProbeURL, probeFallback: defaultProbeFallback,
		dialSlots: make(map[string]*endpointSlots), attempts: attempts, performance: performance,
		recentLimit: recentLimit, recentTTL: recentTTL,
		lookupProcess: process.Lookup, lookupProcessUDP: process.LookupUDP,
	}
	for _, port := range localPorts {
		engine.ports[uint16(port)] = true
	}
	for _, node := range config.Nodes {
		if node.Name == "" || strings.TrimSpace(node.Name) != node.Name || engine.types[node.Name] != "" || (node.Name == "SELECT" || node.Name == "AUTO") {
			return nil, fmt.Errorf("invalid or duplicate node name %q", node.Name)
		}
		if err := node.Validate(); err != nil {
			return nil, fmt.Errorf("node %q: %w", node.Name, err)
		}
		engine.types[node.Name] = node.Type
		engine.servers[node.Name] = node.Server
		engine.order = append(engine.order, node.Name)
	}
	if err := validateNodeReferences(config.Nodes); err != nil {
		return nil, err
	}
	groups, err := validateGroups(config.Groups, func(name string) bool { return engine.types[name] != "" })
	if err != nil {
		return nil, err
	}
	engine.groups = groups
	for _, g := range config.Groups {
		engine.order = append(engine.order, g.Name)
	}
	engine.dataDir = config.DataDir
	if err := engine.openRuleSets(ctx, config, indexes); err != nil {
		return nil, err
	}
	engine.rules, err = newMatcher(config.Rules, func(via string) bool { return engine.valid(via) || via == "SELECT" }, engine.ruleSets)
	if err != nil {
		return nil, err
	}
	interval := defaultProbeInterval
	if config.Health != nil {
		if config.Health.URL != "" {
			if err := validateProbeURL(config.Health.URL); err != nil {
				return nil, err
			}
			engine.probeURL = config.Health.URL
			if config.Health.URL != defaultProbeURL {
				engine.probeFallback = "" // Custom targets require an explicit fallback.
			}
		}
		if config.Health.FallbackURL != "" {
			if err := validateProbeURL(config.Health.FallbackURL); err != nil {
				return nil, err
			}
			engine.probeFallback = config.Health.FallbackURL
		}
		if engine.probeFallback == engine.probeURL {
			engine.probeFallback = ""
		}
		if config.Health.Interval != 0 {
			if config.Health.Interval < 30 {
				return nil, errors.New("health interval must be at least 30 seconds")
			}
			if int64(config.Health.Interval) > math.MaxInt64/int64(time.Second) {
				return nil, errors.New("health interval exceeds the supported duration")
			}
			interval = config.Health.Interval
		}
	}
	if err := engine.SetPolicy(Policy{Mode: config.Mode, Selected: config.Selected}); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if impl == nil {
		return engine, nil // validation only
	}
	if budget == nil {
		budget = newResourceBudget(resources)
	}
	engine.budget = budget
	engine.backend = impl.Name()
	engine.instance, err = impl.Open(config.Nodes, engine.guard)
	if err != nil {
		return nil, err
	}
	for _, node := range config.Nodes {
		engine.dialers[node.Name], _ = engine.instance.Dialer(node.Name)
		engine.dialSlots[node.Name] = budget.dials.retain(endpointKey(node.Server))
	}
	engine.work = lifetime.New()
	engine.ctx = engine.work.Context()
	engine.networkCtx, engine.cancelNetwork = context.WithCancel(engine.ctx)
	engine.ruleRefresh = make(chan struct{}, 1)
	engine.work.Start(engine.ctx, engine.MonitorAuto)
	if len(engine.autoMembers()) != 0 {
		engine.work.Start(engine.ctx, func(ctx context.Context) { engine.healthLoop(ctx, time.Duration(interval)*time.Second) })
	}
	for _, state := range engine.ruleSets {
		if state.URL != "" {
			engine.work.Start(engine.ctx, engine.ruleSetLoop)
			break
		}
	}
	return engine, nil
}

// Validate checks a configuration without opening any node.
func Validate(config Config, impl backend.Backend) error {
	return ValidateContext(context.Background(), config, impl, nil)
}

func ValidateContext(ctx context.Context, config Config, impl backend.Backend, indexes RuleSetIndexes) error {
	if _, err := NewContext(ctx, config, nil, nil, indexes); err != nil {
		return err
	}
	for _, node := range config.Nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := impl.Check(node); err != nil {
			return fmt.Errorf("node %q: %w", node.Name, err)
		}
	}
	return ctx.Err()
}

// NetworkChanged recovers from a network switch or a wake from sleep: cached
// DNS answers and pooled sessions belong to the old network, and node
// latencies must be measured again.
func (engine *Engine) NetworkChanged() {
	engine.mu.Lock()
	if engine.closed {
		engine.mu.Unlock()
		return
	}
	engine.networkEpoch.Add(1)
	if engine.cancelNetwork != nil {
		engine.cancelNetwork()
		engine.networkCtx, engine.cancelNetwork = context.WithCancel(engine.ctx)
	}
	backend.Resolver.Flush()
	if engine.budget != nil {
		engine.budget.dials.changeNetwork()
	}
	if engine.instance != nil {
		engine.instance.ResetConnections()
	}
	clear(engine.health)
	if state := engine.auto; state != nil {
		clear(state.health)
		state.challenger, state.challengerWins = "", 0
		state.orderedCandidates = state.candidates()
		select {
		case engine.autoWake <- struct{}{}:
		default:
		}
	}
	engine.mu.Unlock()
	if members := engine.autoMembers(); len(members) != 0 && engine.ctx != nil {
		engine.work.Start(engine.ctx, func(ctx context.Context) { _ = engine.probeNodes(ctx, members, nil) })
	}
}

// BeginDrain stops new dials and background work on a superseded engine.
// Already established streams continue to use the old engine until closed.
func (engine *Engine) BeginDrain() {
	if engine.work != nil {
		engine.work.Stop()
	}
}

func (engine *Engine) Close() error {
	engine.closeOnce.Do(func() {
		engine.mu.Lock()
		engine.closed = true
		if engine.recentTimer != nil {
			engine.recentTimer.Stop()
			engine.recentTimer = nil
		}
		connections := make([]*tracked, 0, len(engine.live))
		packets := make([]*trackedPacket, 0, len(engine.livePackets))
		for _, conn := range engine.live {
			connections = append(connections, conn)
		}
		for _, conn := range engine.livePackets {
			packets = append(packets, conn)
		}
		engine.mu.Unlock()
		engine.BeginDrain()
		for _, conn := range connections {
			_ = conn.Close()
		}
		for _, conn := range packets {
			_ = conn.Close()
		}
		if engine.work != nil {
			engine.work.Wait()
		}
		if engine.instance != nil {
			engine.closeErr = engine.instance.Close()
		}
		for _, endpoint := range engine.dialSlots {
			engine.budget.dials.release(endpoint)
		}
	})
	return engine.closeErr
}

func (engine *Engine) valid(name string) bool {
	return engine.types[name] != "" || engine.groups[name] != nil
}

func (engine *Engine) ValidatePolicy(policy Policy) error {
	if policy.Mode != "rule" && policy.Mode != "direct" && policy.Mode != "global" && policy.Mode != "auto" {
		return errors.New("mode must be rule, direct, global or auto")
	}
	if policy.Mode == "auto" {
		if err := engine.validateAuto(policy.Auto); err != nil {
			return err
		}
	} else if !engine.valid(policy.Selected) {
		return errors.New("selected outbound does not exist")
	}
	return nil
}

func (engine *Engine) SetPolicy(policy Policy) error {
	if err := engine.ValidatePolicy(policy); err != nil {
		return err
	}
	engine.mu.Lock()
	if engine.auto != nil && engine.auto.cancel != nil {
		engine.auto.cancel()
	}
	engine.auto = nil
	if policy.Mode == "auto" {
		engine.auto = &autoState{config: policy.Auto, unavailable: engine.unavailableProviders(policy.Auto), health: make(map[string]autoNode), activeGroup: -1}
		engine.auto.orderedCandidates = engine.auto.candidates()
	}
	engine.policy = policy
	select {
	case engine.autoWake <- struct{}{}:
	default:
	}
	engine.mu.Unlock()
	return nil
}

func (engine *Engine) guard(peer netip.AddrPort) error {
	if engine.ports[peer.Port()] && (peer.Addr().Unmap().IsLoopback() || peer.Addr().IsUnspecified()) {
		return backend.ErrLoop
	}
	return nil
}

func resolveForRules(ctx context.Context, host string) []netip.Addr {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, _ := backend.Resolver.Lookup(ctx, host)
	return addrs
}

// route picks the outbound name for host. Rules are immutable after New.
type ruleOutcome uint8

const (
	specificRoute ruleOutcome = iota
	explicitMatch
	implicitDefault
)

func (rule Rule) outcome() ruleOutcome {
	if rule.Type == RuleMatch {
		return explicitMatch
	}
	return specificRoute
}

func (engine *Engine) countRuleOutcome(outcome ruleOutcome) {
	switch outcome {
	case explicitMatch:
		engine.explicitMatch.Add(1)
	case implicitDefault:
		engine.implicitDefault.Add(1)
	}
}

func (engine *Engine) route(ctx context.Context, host string, policy Policy, owner func() *process.Owner) (string, string, ruleOutcome) {
	if strings.Contains(host, "%") {
		if addr, err := netip.ParseAddr(host); err == nil && wire.IsScopedLinkLocal(addr) {
			if policy.Mode == "global" && policy.Selected == "REJECT" {
				return "REJECT", "global mode", specificRoute
			}
			if policy.Mode == "rule" {
				index := engine.rules.match(host, nil, owner)
				if index >= 0 {
					rule := engine.rules.rules[index]
					if rule.Via == "REJECT" || rule.Via == "SELECT" && policy.Selected == "REJECT" {
						return "REJECT", rule.String(), rule.outcome()
					}
				}
			}
			return "DIRECT", "IPv6 link-local interface", specificRoute
		}
	}
	switch policy.Mode {
	case "direct":
		return "DIRECT", "direct mode", specificRoute
	case "auto":
		return "AUTO", "automatic · " + policy.Auto.Region, specificRoute
	case "global":
		return policy.Selected, "global mode", specificRoute
	}
	index := engine.rules.match(host, func(name string) []netip.Addr { return resolveForRules(ctx, name) }, owner)
	if index < 0 {
		return "DIRECT", "default", implicitDefault
	}
	rule := engine.rules.rules[index]
	via := rule.Via
	if via == "SELECT" {
		via = policy.Selected
	}
	return via, rule.String(), rule.outcome()
}

// Decide reports the outbound a connection to target would use, without
// dialing. The TUN device uses it for UDP, which HopWay relays only directly.
type RouteDecision struct {
	Rule     string   `json:"rule"`
	Path     []string `json:"path"`
	Outbound string   `json:"outbound"`
}

func (engine *Engine) Explain(target string) (RouteDecision, error) {
	return engine.ExplainContext(context.Background(), target)
}

func (engine *Engine) ExplainContext(ctx context.Context, target string) (RouteDecision, error) {
	host, _, err := wire.Split(target)
	if err != nil {
		return RouteDecision{}, errors.New("expected a host and port")
	}
	engine.mu.Lock()
	policy := engine.policy
	engine.mu.Unlock()
	via, rule, _ := engine.route(ctx, host, policy, nil)
	if err := ctx.Err(); err != nil {
		return RouteDecision{}, err
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if list := engine.choices(via); len(list) != 0 {
		return RouteDecision{Rule: rule, Path: list[0].route, Outbound: list[0].via}, nil
	}
	return RouteDecision{Rule: rule, Outbound: "REJECT"}, nil
}

func (engine *Engine) Decide(target string) string {
	decision, err := engine.Explain(target)
	if err != nil {
		return "REJECT"
	}
	return decision.Outbound
}

func (engine *Engine) Dial(ctx context.Context, inbound, target string) (net.Conn, error) {
	host, _, err := wire.Split(target)
	if err != nil {
		return nil, err
	}
	engine.mu.Lock()
	if engine.closed {
		engine.mu.Unlock()
		return nil, net.ErrClosed
	}
	if !engine.budget.reserveConnection() {
		engine.mu.Unlock()
		return nil, wire.ErrConnectionLimit
	}
	trackedOwnsSlot := false
	defer func() {
		if !trackedOwnsSlot {
			engine.budget.releaseConnection()
		}
	}()
	engine.sequence++
	record := Record{ID: engine.sequence, Start: time.Now().UnixMilli(), Target: target, Inbound: inbound, State: "active"}
	policy := engine.policy
	engine.mu.Unlock()
	ctx, cancel := engine.dialContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Rule evaluation may resolve DNS or look up the process, so it runs
	// outside the lock. The process is looked up here only if a process rule
	// could decide the route; otherwise later, off the connection's path.
	addrs, local := peer.From(ctx)
	local = local && addrs.Local
	var owner *process.Owner
	looked := false
	lookup := func() *process.Owner {
		if !looked && local {
			looked = true
			owner, _ = engine.lookupProcess(addrs.Client, addrs.Server)
		}
		return owner
	}
	via, rule, outcome := engine.route(ctx, host, policy, lookup)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	record.Rule = rule
	engine.countRuleOutcome(outcome)
	engine.mu.Lock()
	candidates := engine.choices(via)
	engine.mu.Unlock()
	if len(candidates) > engine.attempts {
		candidates = candidates[:engine.attempts]
	}

	var conn net.Conn
	for i, candidate := range candidates {
		record.Via, record.Route, record.Attempts = candidate.via, candidate.route, i+1
		attempt := ctx
		cancelAttempt := context.CancelFunc(func() {})
		if i < len(candidates)-1 {
			attempt, cancelAttempt = context.WithTimeout(ctx, engine.performance.failoverTimeout)
		}
		conn, err = engine.dialOnce(attempt, candidate.via, target, &record)
		cancelAttempt()
		if err != nil {
			record.recordAttemptFailure(err)
		}
		if err == nil || ctx.Err() != nil || wire.DescriptorExhausted(err) {
			break
		}
		// Only fail over when the node itself is at fault; a dead target
		// would fail the same way through every node.
		if record.Stage != trace.StageDNS && record.Stage != trace.StageConnect && record.Stage != trace.StageHandshake {
			break
		}
		if candidate.via == "DIRECT" {
			break
		}
	}
	if err != nil && local && ctx.Err() == nil {
		lookup() // the client is still waiting on its socket, so it can be found
	}
	record.setOwner(owner)
	engine.mu.Lock()
	if engine.closed {
		engine.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		return nil, net.ErrClosed
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	if err != nil {
		record.State = "failed"
		record.setFailure(diagnoseDial(err, record.Stage))
		if errors.Is(err, outbound.ErrRejected) {
			record.State, record.Stage = "blocked", trace.StageRoute
		} else if errors.Is(err, context.Canceled) {
			record.State = "canceled"
		}
		engine.remember(record)
		engine.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		return nil, reportedDialError{record.Error, err}
	}
	record.Stage, record.Error, record.FailureCode = "", "", ""
	tracked := &tracked{Conn: conn, engine: engine, record: record, opened: time.Now()}
	trackedOwnsSlot = true
	engine.live[record.ID] = tracked
	engine.peakTCP = max(engine.peakTCP, len(engine.live))
	engine.journal.mark(record.ID, true)
	engine.mu.Unlock()
	if local && !looked {
		go engine.attribute(record.ID, addrs)
	}
	return tracked, nil
}

func (engine *Engine) dialContext(ctx context.Context) (context.Context, context.CancelFunc) {
	engine.mu.Lock()
	network := engine.networkCtx
	engine.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, engine.performance.dialTimeout)
	stop := context.AfterFunc(network, cancel)
	if network.Err() != nil {
		cancel()
	}
	return ctx, func() {
		stop()
		cancel()
	}
}

// attribute fills in the process of a connection after it was established.
func (engine *Engine) attribute(id uint64, addrs peer.Addrs) {
	owner, err := engine.lookupProcess(addrs.Client, addrs.Server)
	if err != nil || owner == nil {
		return
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if conn := engine.live[id]; conn != nil {
		conn.record.setOwner(owner)
		engine.journal.mark(id, true)
		return
	}
	if record := engine.recent.get(id); record != nil {
		record.setOwner(owner)
		engine.journal.mark(id, true)
	}
}

func (record *Record) setOwner(owner *process.Owner) {
	if owner != nil {
		record.Process, record.ProcessPath, record.ProcessBundleID, record.PID = owner.Label(), owner.Path, owner.BundleID, owner.PID
	}
}

// DialPacket opens a UDP session for traffic to target, routed and
// recorded like TCP. The returned connection's WriteTo takes M.Socksaddr
// destinations (names allowed); ReadFrom reports the address written to.
func (engine *Engine) DialPacket(ctx context.Context, inbound, target string) (net.PacketConn, error) {
	host, _, err := wire.Split(target)
	if err != nil {
		return nil, err
	}
	select {
	case engine.budget.opening <- struct{}{}:
		defer func() { <-engine.budget.opening }()
	default:
		return nil, backend.ErrPacketCongested
	}
	engine.mu.Lock()
	if engine.closed {
		engine.mu.Unlock()
		return nil, net.ErrClosed
	}
	if !engine.budget.reserveConnection() {
		engine.mu.Unlock()
		return nil, wire.ErrConnectionLimit
	}
	trackedOwnsSlot := false
	defer func() {
		if !trackedOwnsSlot {
			engine.budget.releaseConnection()
		}
	}()
	engine.sequence++
	record := Record{ID: engine.sequence, Start: time.Now().UnixMilli(), Target: target, Inbound: inbound, State: "active", Network: "udp"}
	policy := engine.policy
	engine.mu.Unlock()
	ctx, cancel := engine.dialContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addrs, local := peer.From(ctx)
	local = local && addrs.Local
	var owner *process.Owner
	looked := false
	lookup := func() *process.Owner {
		if !looked && local {
			looked = true
			owner, _ = engine.lookupProcessUDP(addrs.Client, addrs.Server)
		}
		return owner
	}
	via, rule, outcome := engine.route(ctx, host, policy, lookup)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	record.Rule = rule
	engine.countRuleOutcome(outcome)
	engine.mu.Lock()
	candidates := engine.choices(via)
	engine.mu.Unlock()
	if len(candidates) > engine.attempts {
		candidates = candidates[:engine.attempts]
	}
	var conn net.PacketConn
	var exit *packetOutbound
	for i, candidate := range candidates {
		record.Via, record.Route, record.Attempts = candidate.via, candidate.route, i+1
		attempt, timing := trace.With(ctx)
		conn, exit, err = engine.openPacket(attempt, candidate.via, target)
		record.Server, _, _, _, record.Stage = timing.Snapshot()
		if err != nil {
			record.recordAttemptFailure(err)
		}
		if err == nil || errors.Is(err, outbound.ErrRejected) || ctx.Err() != nil ||
			record.Stage == trace.StageUpstream || wire.DescriptorExhausted(err) {
			break
		}
	}
	if local && ctx.Err() == nil {
		lookup()
	}
	record.setOwner(owner)
	engine.mu.Lock()
	if engine.closed {
		err = net.ErrClosed
	} else if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		record.State = "failed"
		record.setFailure(diagnoseDial(err, record.Stage))
		if errors.Is(err, outbound.ErrRejected) {
			record.State, record.Stage = "blocked", trace.StageRoute
		}
		engine.remember(record)
		engine.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
			engine.budget.releaseOutbound(exit)
		}
		return nil, reportedDialError{record.Error, err}
	}
	record.Stage, record.Error, record.FailureCode = "", "", ""
	tracked := &trackedPacket{PacketConn: conn, engine: engine, record: record, outbound: exit}
	trackedOwnsSlot = true
	evicted := engine.budget.admit(tracked)
	engine.livePackets[record.ID] = tracked
	engine.peakUDP = max(engine.peakUDP, len(engine.livePackets))
	engine.journal.mark(record.ID, true)
	engine.mu.Unlock()
	if evicted != nil {
		_ = evicted.Close()
	}
	return tracked, nil
}

func (engine *Engine) openPacket(ctx context.Context, via, target string) (net.PacketConn, *packetOutbound, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if via == "REJECT" {
		return nil, nil, outbound.ErrRejected
	}
	key := via
	if endpoint := engine.dialSlots[via]; endpoint != nil {
		key = endpoint.key
	}
	exit := engine.budget.retainOutbound(key)
	select {
	case exit.opening <- struct{}{}:
		defer func() { <-exit.opening }()
	default:
		engine.budget.releaseOutbound(exit)
		return nil, nil, backend.ErrPacketCongested
	}
	conn, err := engine.dialPacketOnce(ctx, via, target)
	if err != nil {
		engine.budget.releaseOutbound(exit)
		return nil, nil, err
	}
	return conn, exit, nil
}

func (engine *Engine) dialPacketOnce(ctx context.Context, via, target string) (net.PacketConn, error) {
	switch via {
	case "DIRECT":
		return backend.DirectPacket(ctx, target, engine.guard)
	case "REJECT":
		return nil, outbound.ErrRejected
	}
	dialer, ok := engine.dialers[via].(backend.PacketDialer)
	if !ok {
		return nil, backend.ErrNoUDP
	}
	slot, err := engine.acquireDialSlot(via)
	if err != nil {
		return nil, err
	}
	if slot != nil {
		defer engine.budget.dials.finish(slot)
	}
	return dialer.ListenPacket(engine.withEndpointGate(ctx, via), target)
}

type trackedPacket struct {
	net.PacketConn
	engine     *Engine
	record     Record
	sent, recv atomic.Uint64
	sampled    ConnectionCounters // guarded by engine.mu
	outbound   *packetOutbound
	lastActive atomic.Int64
	closed     atomic.Bool
	once       sync.Once
}

func (conn *trackedPacket) ReadFrom(data []byte) (int, net.Addr, error) {
	if conn.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	n, addr, err := conn.PacketConn.ReadFrom(data)
	if conn.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	conn.recv.Add(uint64(max(n, 0)))
	if err == nil {
		conn.touch()
	}
	if n > 0 {
		conn.engine.traffic.add(time.Now(), conn.record.Via, 0, uint64(n))
	}
	return n, addr, err
}

func (conn *trackedPacket) WriteTo(data []byte, addr net.Addr) (int, error) {
	if conn.closed.Load() {
		return 0, net.ErrClosed
	}
	select {
	case conn.outbound.sending <- struct{}{}:
		defer func() {
			<-conn.outbound.sending
			if conn.outbound.refs.Load() == 0 {
				conn.engine.budget.pruneOutbound(conn.outbound)
			}
		}()
	default:
		return 0, backend.ErrPacketCongested
	}
	if conn.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := conn.PacketConn.WriteTo(data, addr)
	if err == nil {
		conn.touch()
	}
	conn.sent.Add(uint64(max(n, 0)))
	if n > 0 {
		conn.engine.traffic.add(time.Now(), conn.record.Via, uint64(n), 0)
	}
	return n, err
}

func (conn *trackedPacket) touch() {
	conn.lastActive.Store(time.Since(conn.engine.budget.started).Nanoseconds())
}

func (conn *trackedPacket) snapshot() Record {
	record := conn.record
	record.Sent, record.Recv = conn.sent.Load(), conn.recv.Load()
	return record
}

func (conn *trackedPacket) Close() error {
	var err error
	conn.once.Do(func() {
		defer conn.engine.budget.releaseConnection()
		conn.closed.Store(true)
		err = conn.PacketConn.Close()
		conn.engine.budget.remove(conn)
		conn.engine.mu.Lock()
		defer conn.engine.mu.Unlock()
		record := conn.snapshot()
		record.State = "closed"
		delete(conn.engine.livePackets, record.ID)
		conn.engine.livePackets = shrinkConnectionIndex(conn.engine.livePackets, &conn.engine.peakUDP)
		conn.engine.remember(record)
	})
	return err
}

// dialOnce dials through one node and fills in stage timings.
func (engine *Engine) dialOnce(ctx context.Context, via, target string, record *Record) (net.Conn, error) {
	slot, err := engine.acquireDialSlot(via)
	if err != nil {
		record.Stage = trace.StageConnect
		return nil, err
	}
	if slot != nil {
		defer engine.budget.dials.finish(slot)
	}
	epoch := engine.networkEpoch.Load()
	ctx, t := trace.With(ctx)
	start := time.Now()
	var conn net.Conn
	switch via {
	case "DIRECT":
		conn, err = backend.NetDial(ctx, "tcp", target, engine.guard)
	case "REJECT":
		err = outbound.ErrRejected
	default:
		dialer := engine.dialers[via]
		if dialer == nil {
			err = errors.New("outbound is not available")
		} else {
			conn, err = dialer.DialContext(engine.withEndpointGate(ctx, via), target)
		}
	}
	total := time.Since(start)
	server, dns, connect, reached, failStage := t.Snapshot()
	record.Server, record.DNSMs, record.ConnectMs = server, dns.Milliseconds(), connect.Milliseconds()
	record.HandshakeMs, record.Shared = 0, false
	if via != "DIRECT" && reached {
		record.HandshakeMs = max(total-dns-connect, 0).Milliseconds()
	}
	if server == "" && engine.servers[via] != "" {
		// gRPC, QUIC and mux transports open their socket on a background
		// context and share it; the stream itself took only total.
		record.Server, record.Shared, record.HandshakeMs = engine.servers[via], true, total.Milliseconds()
	}
	record.Stage = ""
	if err != nil {
		switch {
		case failStage != "":
			record.Stage = failStage
		case via == "REJECT":
			record.Stage = trace.StageRoute
		default:
			// Reached the server (or reused a session) but the protocol failed.
			record.Stage = trace.StageHandshake
		}
		record.setFailure(diagnoseDial(err, record.Stage))
	}
	if via != "DIRECT" && via != "REJECT" && !errors.Is(ctx.Err(), context.Canceled) &&
		!errors.Is(err, backend.ErrEndpointCooling) && !wire.DescriptorExhausted(err) {
		engine.mu.Lock()
		if engine.networkEpoch.Load() != epoch {
			engine.mu.Unlock()
			return conn, err
		}
		h := engine.health[via]
		if err != nil && record.Stage != trace.StageRoute && record.Stage != trace.StageUpstream {
			if h == nil {
				h = &nodeHealth{}
				engine.health[via] = h
			}
			h.alive, h.checked, h.err = false, time.Now(), record.Error
			h.stage, h.code, h.target = record.Stage, record.FailureCode, ""
		} else if err == nil {
			if h == nil {
				h = &nodeHealth{}
				engine.health[via] = h
			}
			now := time.Now()
			if !h.alive {
				h.alive, h.err, h.stage, h.code, h.target = true, "", "", "", ""
				h.latency = 0
			}
			if h.target == "" {
				h.checked = now
			}
			h.succeeded = now
		}
		engine.mu.Unlock()
	}
	return conn, err
}

func (engine *Engine) Status() Status {
	return engine.status(true)
}

func (engine *Engine) CompactStatus() Status {
	return engine.status(false)
}

func (engine *Engine) status(includeConnections bool) Status {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	status := Status{Backend: engine.backend, Policy: engine.policy, Active: len(engine.live) + len(engine.livePackets),
		RuleSets: engine.ruleSetStatus(), SessionTraffic: engine.traffic.sessionTotals(),
		RuleDefaults: RuleDefaults{ExplicitMatch: engine.explicitMatch.Load(), Implicit: engine.implicitDefault.Load()}}
	if engine.budget != nil {
		status.Resources = engine.budget.status()
	}
	if includeConnections {
		status.Connections = engine.connectionSnapshot()
	}
	for _, inbound := range [...]struct {
		name  string
		drops wire.UDPDropCounts
	}{{"SOCKS5", wire.SOCKSUDPDrops.Snapshot()}, {"TUN", wire.TUNUDPDrops.Snapshot()}} {
		if inbound.drops != (wire.UDPDropCounts{}) {
			if status.UDPDrops == nil {
				status.UDPDrops = make(map[string]wire.UDPDropCounts, 2)
			}
			status.UDPDrops[inbound.name] = inbound.drops
		}
	}
	if state := engine.auto; state != nil {
		status.Auto = &AutoStatus{Node: state.activeNode, Probing: state.probing}
		if state.activeGroup >= 0 {
			status.Auto.Provider = state.config.Groups[state.activeGroup].Name
		}
	}
	for _, name := range engine.order {
		summary := NodeSummary{Name: name, Type: engine.types[name]}
		if g := engine.groups[name]; g != nil {
			summary.Type = "group"
			now := ""
			if list := engine.choices(name); len(list) != 0 {
				now = list[0].via
			}
			status.Groups = append(status.Groups, GroupStatus{Name: name, Type: g.Type, Members: g.Members, Now: now, Selected: g.Selected})
		}
		if h := engine.health[name]; h != nil {
			alive := h.alive
			summary.Alive, summary.Error = &alive, h.err
			summary.FailureStage, summary.FailureCode, summary.ProbeTarget = h.stage, h.code, h.target
			observed := h.checked
			if observed.IsZero() {
				observed = h.succeeded
			}
			if !observed.IsZero() {
				summary.HealthAt = observed.UnixMilli()
			}
			if h.alive && h.latency > 0 {
				summary.LatencyMs = max(h.latency.Milliseconds(), 1)
			}
		}
		status.Nodes = append(status.Nodes, summary)
	}
	return status
}

type tracked struct {
	net.Conn
	engine     *Engine
	record     Record
	opened     time.Time
	sent, recv atomic.Uint64
	firstByte  atomic.Int64
	sampled    ConnectionCounters // guarded by engine.mu
	relayErr   atomic.Pointer[wire.RelayError]
	once       sync.Once
}

func (conn *tracked) snapshot() Record {
	record := conn.record
	record.Sent, record.Recv = conn.sent.Load(), conn.recv.Load()
	record.FirstByteMs = conn.firstByte.Load()
	return record
}

func (conn *tracked) Read(data []byte) (int, error) {
	count, err := conn.Conn.Read(data)
	if conn.engine.traffic != nil && count > 0 {
		conn.engine.traffic.add(time.Now(), conn.record.Via, 0, uint64(count))
	}
	if count > 0 && conn.recv.Add(uint64(count)) == uint64(count) {
		conn.firstByte.Store(max(time.Since(conn.opened).Milliseconds(), 1))
	}
	return count, err
}

func (conn *tracked) Write(data []byte) (int, error) {
	count, err := conn.Conn.Write(data)
	if conn.engine.traffic != nil && count > 0 {
		conn.engine.traffic.add(time.Now(), conn.record.Via, uint64(count), 0)
	}
	conn.sent.Add(uint64(count))
	return count, err
}

func (conn *tracked) CloseWrite() error {
	return wire.CloseWrite(conn.Conn)
}

func (conn *tracked) RecordRelayError(failure *wire.RelayError) {
	if !errors.Is(failure.Err, net.ErrClosed) {
		conn.relayErr.CompareAndSwap(nil, failure)
	}
}

func (conn *tracked) Close() error {
	var err error
	conn.once.Do(func() {
		defer conn.engine.budget.releaseConnection()
		err = conn.Conn.Close()
		conn.engine.mu.Lock()
		defer conn.engine.mu.Unlock()
		record := conn.snapshot()
		record.State = "closed"
		// Protocols such as VLESS and Trojan finish their handshake lazily: a
		// bad credential shows up as the server hanging up before any reply.
		if failure := conn.relayErr.Load(); failure != nil {
			record.State = "failed"
			record.Stage = failure.Endpoint + "-" + failure.Operation
			record.setFailure(diagnoseDial(failure.Err, record.Stage))
		} else if record.Sent > 0 && record.Recv == 0 && record.Via != "DIRECT" {
			record.State, record.Stage = "failed", trace.StageUpstream
			record.Error = "the proxy closed the connection without a response"
			record.FailureCode = "upstream-no-response"
		}
		delete(conn.engine.live, record.ID)
		conn.engine.live = shrinkConnectionIndex(conn.engine.live, &conn.engine.peakTCP)
		conn.engine.remember(record)
	})
	return err
}
