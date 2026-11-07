package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/outbound"
	"mac-proxy/internal/peer"
	"mac-proxy/internal/process"
	"mac-proxy/internal/trace"
	"mac-proxy/internal/wire"
)

type Config struct {
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
	Subscriptions []Subscription `json:"subscriptions,omitempty"`
	// SystemProxy points macOS's proxy settings at HopWay while it runs.
	SystemProxy bool `json:"systemProxy,omitempty"`
	// TUN captures all traffic through a virtual network device.
	TUN *TUNConfig `json:"tun,omitempty"`

	// DataDir holds caches (downloaded rule sets). Set by the caller, not saved.
	DataDir string `json:"-"`
}

type TUNConfig struct {
	Enabled bool   `json:"enabled"`
	MTU     uint32 `json:"mtu,omitempty"`
}

// Subscription is a remote node list refreshed in the background.
type Subscription struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Interval int    `json:"intervalSec,omitempty"` // default 12 hours
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
	return *config, nil
}

type Policy struct {
	Mode     string `json:"mode"`
	Selected string `json:"selected"`
}

type NodeSummary struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	LatencyMs int64  `json:"latencyMs,omitempty"`
	Alive     *bool  `json:"alive,omitempty"`
	Error     string `json:"error,omitempty"`
}

type GroupStatus struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Members []string `json:"members"`
	Now     string   `json:"now"` // node currently used
}

// Record describes one connection. Timings are milliseconds.
type Record struct {
	ID          uint64   `json:"id"`
	Start       int64    `json:"start"`
	Inbound     string   `json:"inbound"`
	Target      string   `json:"target"`
	Via         string   `json:"via"`
	Route       []string `json:"route,omitempty"`
	Rule        string   `json:"rule"`
	State       string   `json:"state"`
	Sent        uint64   `json:"sent"`
	Recv        uint64   `json:"received"`
	Error       string   `json:"error,omitempty"`
	Stage       string   `json:"stage,omitempty"`
	Server      string   `json:"server,omitempty"`
	Shared      bool     `json:"shared,omitempty"`      // rode a multiplexed session, no socket of its own
	Network     string   `json:"network,omitempty"`     // "udp" for datagram sessions
	Process     string   `json:"process,omitempty"`     // app or executable name
	ProcessPath string   `json:"processPath,omitempty"` // executable path
	PID         uint32   `json:"pid,omitempty"`
	Attempts    int      `json:"attempts,omitempty"`
	DNSMs       int64    `json:"dnsMs,omitempty"`
	ConnectMs   int64    `json:"connectMs,omitempty"`
	HandshakeMs int64    `json:"handshakeMs,omitempty"`
	FirstByteMs int64    `json:"firstByteMs,omitempty"`
}

type Status struct {
	Backend     string          `json:"backend"`
	Policy      Policy          `json:"policy"`
	Nodes       []NodeSummary   `json:"nodes"`
	Groups      []GroupStatus   `json:"groups,omitempty"`
	RuleSets    []RuleSetStatus `json:"ruleSets,omitempty"`
	Connections []Record        `json:"connections"`
	Active      int             `json:"active"`
}

type Engine struct {
	mu          sync.Mutex
	policy      Policy
	backend     string
	instance    backend.Instance
	dialers     map[string]backend.Dialer
	types       map[string]string
	servers     map[string]string
	order       []string
	groups      map[string]*group
	health      map[string]*nodeHealth
	rules       *matcher
	probeURL    string
	sequence    uint64
	live        map[uint64]*tracked
	livePackets map[uint64]*trackedPacket
	recent      []Record
	ports       map[uint16]bool
	stop        context.CancelFunc

	lookupProcess    func(client, server netip.AddrPort) (*process.Owner, error)
	lookupProcessUDP func(client, server netip.AddrPort) (*process.Owner, error)
	dataDir          string
	ruleSets         []*ruleSetState
}

const (
	dialTimeout    = 10 * time.Second
	attemptTimeout = 5 * time.Second
	maxAttempts    = 3
)

// New builds an engine; localPorts are HopWay's own listeners, which no
// connection may be sent back to.
func New(config Config, impl backend.Backend, localPorts ...int) (*Engine, error) {
	if config.SOCKSPort < 0 || config.SOCKSPort > 65535 || config.HTTPPort < 0 || config.HTTPPort > 65535 ||
		(config.SOCKSPort != 0 && config.SOCKSPort == config.HTTPPort) {
		return nil, errors.New("proxy ports must be distinct or 0 for automatic assignment")
	}
	engine := &Engine{dialers: make(map[string]backend.Dialer), types: map[string]string{"DIRECT": "direct", "REJECT": "reject"}, servers: map[string]string{},
		order: []string{"DIRECT", "REJECT"}, health: make(map[string]*nodeHealth),
		live: make(map[uint64]*tracked), livePackets: make(map[uint64]*trackedPacket), ports: make(map[uint16]bool), probeURL: defaultProbeURL,
		lookupProcess: process.Lookup, lookupProcessUDP: process.LookupUDP,
	}
	for _, port := range localPorts {
		engine.ports[uint16(port)] = true
	}
	for _, node := range config.Nodes {
		if node.Name == "" || strings.TrimSpace(node.Name) != node.Name || engine.types[node.Name] != "" || node.Name == "SELECT" {
			return nil, fmt.Errorf("invalid or duplicate node name %q", node.Name)
		}
		if err := node.Validate(); err != nil {
			return nil, fmt.Errorf("node %q: %w", node.Name, err)
		}
		engine.types[node.Name] = node.Type
		engine.servers[node.Name] = node.Server
		engine.order = append(engine.order, node.Name)
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
	sets, err := engine.openRuleSets(config)
	if err != nil {
		return nil, err
	}
	engine.rules, err = newMatcher(config.Rules, func(via string) bool { return engine.valid(via) || via == "SELECT" }, sets)
	if err != nil {
		return nil, err
	}
	interval := defaultProbeInterval
	if config.Health != nil {
		if config.Health.URL != "" {
			if !strings.HasPrefix(config.Health.URL, "http://") && !strings.HasPrefix(config.Health.URL, "https://") {
				return nil, errors.New("health URL must be http or https")
			}
			engine.probeURL = config.Health.URL
		}
		if config.Health.Interval != 0 {
			if config.Health.Interval < 30 {
				return nil, errors.New("health interval must be at least 30 seconds")
			}
			interval = config.Health.Interval
		}
	}
	if err := engine.SetPolicy(Policy{config.Mode, config.Selected}); err != nil {
		return nil, err
	}
	if impl == nil {
		return engine, nil // validation only
	}
	engine.backend = impl.Name()
	engine.instance, err = impl.Open(config.Nodes, engine.guard)
	if err != nil {
		return nil, err
	}
	for _, node := range config.Nodes {
		engine.dialers[node.Name], _ = engine.instance.Dialer(node.Name)
	}
	ctx, cancel := context.WithCancel(context.Background())
	engine.stop = cancel
	if len(engine.autoMembers()) != 0 {
		go engine.healthLoop(ctx, time.Duration(interval)*time.Second)
	}
	for _, state := range engine.ruleSets {
		if state.URL != "" {
			go engine.ruleSetLoop(ctx)
			break
		}
	}
	return engine, nil
}

// Validate checks a configuration without opening any node.
func Validate(config Config, impl backend.Backend) error {
	if _, err := New(config, nil); err != nil {
		return err
	}
	for _, node := range config.Nodes {
		if err := impl.Check(node); err != nil {
			return fmt.Errorf("node %q: %w", node.Name, err)
		}
	}
	return nil
}

// NetworkChanged recovers from a network switch or a wake from sleep: cached
// DNS answers and pooled sessions belong to the old network, and node
// latencies must be measured again.
func (engine *Engine) NetworkChanged() {
	backend.Resolver.Flush()
	if engine.instance != nil {
		engine.instance.ResetConnections()
	}
	engine.mu.Lock()
	for _, h := range engine.health {
		h.checked = time.Time{} // unknown again until probed
	}
	engine.mu.Unlock()
	if members := engine.autoMembers(); len(members) != 0 && engine.stop != nil {
		go engine.Probe(context.Background(), members)
	}
}

func (engine *Engine) Close() error {
	if engine.stop != nil {
		engine.stop()
	}
	if engine.instance != nil {
		return engine.instance.Close()
	}
	return nil
}

func (engine *Engine) valid(name string) bool {
	return engine.types[name] != "" || engine.groups[name] != nil
}

func (engine *Engine) SetPolicy(policy Policy) error {
	if policy.Mode != "rule" && policy.Mode != "direct" && policy.Mode != "global" {
		return errors.New("mode must be rule, direct or global")
	}
	if !engine.valid(policy.Selected) {
		return errors.New("selected outbound does not exist")
	}
	engine.mu.Lock()
	engine.policy = policy
	engine.mu.Unlock()
	return nil
}

func (engine *Engine) guard(peer netip.AddrPort) error {
	if engine.ports[peer.Port()] && (peer.Addr().Unmap().IsLoopback() || peer.Addr().IsUnspecified()) {
		return backend.ErrLoop
	}
	return nil
}

func resolveForRules(host string) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, _ := backend.Resolver.Lookup(ctx, host)
	return addrs
}

// route picks the outbound name for host. Rules are immutable after New.
func (engine *Engine) route(host string, policy Policy, owner func() *process.Owner) (string, string) {
	switch policy.Mode {
	case "direct":
		return "DIRECT", "direct mode"
	case "global":
		return policy.Selected, "global mode"
	}
	index := engine.rules.match(host, resolveForRules, owner)
	if index < 0 {
		return "DIRECT", "default"
	}
	rule := engine.rules.rules[index]
	via := rule.Via
	if via == "SELECT" {
		via = policy.Selected
	}
	return via, rule.String()
}

// Decide reports the outbound a connection to target would use, without
// dialing. The TUN device uses it for UDP, which HopWay relays only directly.
func (engine *Engine) Decide(target string) string {
	host, _, err := wire.Split(target)
	if err != nil {
		return "REJECT"
	}
	engine.mu.Lock()
	policy := engine.policy
	engine.mu.Unlock()
	via, _ := engine.route(host, policy, nil)
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if list := engine.choices(via); len(list) != 0 {
		return list[0].via
	}
	return "REJECT"
}

func (engine *Engine) Dial(ctx context.Context, inbound, target string) (net.Conn, error) {
	host, _, err := wire.Split(target)
	if err != nil {
		return nil, err
	}
	engine.mu.Lock()
	engine.sequence++
	record := Record{ID: engine.sequence, Start: time.Now().UnixMilli(), Target: target, Inbound: inbound, State: "active"}
	policy := engine.policy
	engine.mu.Unlock()

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
	via, rule := engine.route(host, policy, lookup)
	record.Rule = rule
	engine.mu.Lock()
	candidates := engine.choices(via)
	engine.mu.Unlock()
	if len(candidates) > maxAttempts {
		candidates = candidates[:maxAttempts]
	}

	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var conn net.Conn
	for i, candidate := range candidates {
		record.Via, record.Route, record.Attempts = candidate.via, candidate.route, i+1
		attempt := ctx
		cancelAttempt := context.CancelFunc(func() {})
		if i < len(candidates)-1 {
			attempt, cancelAttempt = context.WithTimeout(ctx, attemptTimeout)
		}
		conn, err = engine.dialOnce(attempt, candidate.via, target, &record)
		cancelAttempt()
		if err == nil || ctx.Err() != nil {
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
	if err != nil && local {
		lookup() // the client is still waiting on its socket, so it can be found
	}
	record.setOwner(owner)
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if err != nil {
		record.State, record.Error = "failed", describe(err)
		if errors.Is(err, outbound.ErrRejected) {
			record.State, record.Stage = "blocked", trace.StageRoute
		}
		engine.remember(record)
		return nil, err
	}
	record.Stage, record.Error = "", ""
	tracked := &tracked{Conn: conn, engine: engine, record: record, opened: time.Now()}
	engine.live[record.ID] = tracked
	if local && !looked {
		go engine.attribute(record.ID, addrs)
	}
	return tracked, nil
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
		return
	}
	for i := len(engine.recent) - 1; i >= 0; i-- {
		if engine.recent[i].ID == id {
			engine.recent[i].setOwner(owner)
			return
		}
	}
}

func (record *Record) setOwner(owner *process.Owner) {
	if owner != nil {
		record.Process, record.ProcessPath, record.PID = owner.Label(), owner.Path, owner.PID
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
	engine.mu.Lock()
	engine.sequence++
	record := Record{ID: engine.sequence, Start: time.Now().UnixMilli(), Target: target, Inbound: inbound, State: "active", Network: "udp"}
	policy := engine.policy
	engine.mu.Unlock()
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
	via, rule := engine.route(host, policy, lookup)
	record.Rule = rule
	engine.mu.Lock()
	candidates := engine.choices(via)
	engine.mu.Unlock()
	if len(candidates) > maxAttempts {
		candidates = candidates[:maxAttempts]
	}
	var conn net.PacketConn
	for i, candidate := range candidates {
		record.Via, record.Route, record.Attempts = candidate.via, candidate.route, i+1
		conn, err = engine.dialPacketOnce(ctx, candidate.via, target)
		if err == nil || errors.Is(err, outbound.ErrRejected) || ctx.Err() != nil {
			break
		}
	}
	if local {
		lookup()
	}
	record.setOwner(owner)
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if err != nil {
		record.State, record.Error = "failed", describe(err)
		if errors.Is(err, outbound.ErrRejected) {
			record.State, record.Stage = "blocked", trace.StageRoute
		}
		engine.remember(record)
		return nil, err
	}
	tracked := &trackedPacket{PacketConn: conn, engine: engine, record: record}
	engine.livePackets[record.ID] = tracked
	return tracked, nil
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
	return dialer.ListenPacket(ctx, target)
}

type trackedPacket struct {
	net.PacketConn
	engine     *Engine
	record     Record
	sent, recv atomic.Uint64
	once       sync.Once
}

func (conn *trackedPacket) ReadFrom(data []byte) (int, net.Addr, error) {
	n, addr, err := conn.PacketConn.ReadFrom(data)
	conn.recv.Add(uint64(max(n, 0)))
	return n, addr, err
}

func (conn *trackedPacket) WriteTo(data []byte, addr net.Addr) (int, error) {
	n, err := conn.PacketConn.WriteTo(data, addr)
	conn.sent.Add(uint64(max(n, 0)))
	return n, err
}

func (conn *trackedPacket) snapshot() Record {
	record := conn.record
	record.Sent, record.Recv = conn.sent.Load(), conn.recv.Load()
	return record
}

func (conn *trackedPacket) Close() error {
	var err error
	conn.once.Do(func() {
		err = conn.PacketConn.Close()
		conn.engine.mu.Lock()
		defer conn.engine.mu.Unlock()
		record := conn.snapshot()
		record.State = "closed"
		delete(conn.engine.livePackets, record.ID)
		conn.engine.remember(record)
	})
	return err
}

// dialOnce dials through one node and fills in stage timings.
func (engine *Engine) dialOnce(ctx context.Context, via, target string, record *Record) (net.Conn, error) {
	ctx, t := trace.With(ctx)
	start := time.Now()
	var conn net.Conn
	var err error
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
			conn, err = dialer.DialContext(ctx, target)
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
	}
	if via != "DIRECT" && via != "REJECT" {
		engine.mu.Lock()
		h := engine.health[via]
		if err != nil && record.Stage != trace.StageRoute {
			if h == nil {
				h = &nodeHealth{}
				engine.health[via] = h
			}
			h.alive, h.checked, h.err = false, time.Now(), describe(err)
		} else if err == nil && h != nil && !h.alive {
			h.alive, h.err = true, ""
		}
		engine.mu.Unlock()
	}
	return conn, err
}

func describe(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return err.Error()
}

func (engine *Engine) remember(record Record) {
	const limit = 300
	if len(engine.recent) == limit {
		copy(engine.recent, engine.recent[1:])
		engine.recent = engine.recent[:limit-1]
	}
	engine.recent = append(engine.recent, record)
}

func (engine *Engine) Status() Status {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	records := make([]Record, 0, len(engine.live)+len(engine.recent))
	for _, conn := range engine.live {
		records = append(records, conn.snapshot())
	}
	for _, conn := range engine.livePackets {
		records = append(records, conn.snapshot())
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	records = append(records, engine.recent...)
	status := Status{Backend: engine.backend, Policy: engine.policy, Connections: records, Active: len(engine.live) + len(engine.livePackets),
		RuleSets: engine.ruleSetStatus()}
	for _, name := range engine.order {
		summary := NodeSummary{Name: name, Type: engine.types[name]}
		if g := engine.groups[name]; g != nil {
			summary.Type = "group"
			now := ""
			if list := engine.choices(name); len(list) != 0 {
				now = list[0].via
			}
			status.Groups = append(status.Groups, GroupStatus{Name: name, Type: g.Type, Members: g.Members, Now: now})
		}
		if h := engine.health[name]; h != nil {
			alive := h.alive
			summary.Alive, summary.Error = &alive, h.err
			if h.alive {
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
	readErr    atomic.Value
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
	if count > 0 && conn.recv.Add(uint64(count)) == uint64(count) {
		conn.firstByte.Store(max(time.Since(conn.opened).Milliseconds(), 1))
	}
	if err != nil && conn.recv.Load() == 0 {
		conn.readErr.CompareAndSwap(nil, err.Error())
	}
	return count, err
}

func (conn *tracked) Write(data []byte) (int, error) {
	count, err := conn.Conn.Write(data)
	conn.sent.Add(uint64(count))
	return count, err
}

func (conn *tracked) CloseWrite() error {
	return wire.CloseWrite(conn.Conn)
}

func (conn *tracked) Close() error {
	var err error
	conn.once.Do(func() {
		err = conn.Conn.Close()
		conn.engine.mu.Lock()
		defer conn.engine.mu.Unlock()
		record := conn.snapshot()
		record.State = "closed"
		// Protocols such as VLESS and Trojan finish their handshake lazily: a
		// bad credential shows up as the server hanging up before any reply.
		if record.Sent > 0 && record.Recv == 0 && record.Via != "DIRECT" {
			record.State, record.Stage = "failed", trace.StageUpstream
			record.Error = "the proxy closed the connection without a response"
			if text, ok := conn.readErr.Load().(string); ok && text != "EOF" {
				record.Error += " (" + text + ")"
			}
		}
		delete(conn.engine.live, record.ID)
		conn.engine.remember(record)
	})
	return err
}
