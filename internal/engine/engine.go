package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"mac-proxy/internal/outbound"
	"mac-proxy/internal/wire"
)

type Config struct {
	SOCKSPort int             `json:"socksPort"`
	HTTPPort  int             `json:"httpPort"`
	Mode      string          `json:"mode"`
	Selected  string          `json:"selected"`
	Nodes     []outbound.Node `json:"nodes"`
	Rules     []Rule          `json:"rules"`
	// Subscriptions lists the providers imported by URL, with their plan usage.
	Subscriptions []Subscription `json:"subscriptions,omitempty"`
}

type Rule struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Via   string `json:"via"`
	cidr  netip.Prefix
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
	Name         string `json:"name"`
	Type         string `json:"type"`
	Subscription string `json:"subscription,omitempty"`
	// Health is "ok", "down" or empty when the node has not been checked yet.
	Health    string `json:"health,omitempty"`
	LatencyMS int64  `json:"latency,omitempty"`
	// Spent is true when the node's plan is used up or expired; AUTO skips it.
	Spent bool `json:"spent,omitempty"`
	// Sent and Recv count bytes through this outbound since the core started.
	Sent uint64 `json:"sent"`
	Recv uint64 `json:"received"`
}

type Record struct {
	ID      uint64 `json:"id"`
	Inbound string `json:"inbound"`
	Target  string `json:"target"`
	Via     string `json:"via"`
	Rule    string `json:"rule"`
	State   string `json:"state"`
	Sent    uint64 `json:"sent"`
	Recv    uint64 `json:"received"`
	Error   string `json:"error,omitempty"`
}

type Status struct {
	Policy      Policy        `json:"policy"`
	Nodes       []NodeSummary `json:"nodes"`
	Connections []Record      `json:"connections"`
	Active      int           `json:"active"`
	// Auto is the node AUTO currently resolves to.
	Auto string `json:"auto"`
	// Subscriptions mirrors the loaded config, including plan usage.
	Subscriptions []Subscription `json:"subscriptions"`
	// Revision increases each time a new config is loaded with Reload.
	Revision uint64 `json:"revision"`
}

type Engine struct {
	mu       sync.Mutex
	policy   Policy
	nodes    map[string]outbound.Node
	summary  []NodeSummary
	rules    []Rule
	sequence uint64
	live     map[uint64]*tracked
	recent   []Record
	ports    map[uint16]bool
	order    []string
	spent    map[string]bool
	health   map[string]*health
	usage    map[string]*counter
	trigger  chan struct{}
	plans    []Subscription
	revision uint64
}

func New(config Config, localPorts ...int) (*Engine, error) {
	if config.SOCKSPort < 0 || config.SOCKSPort > 65535 || config.HTTPPort < 0 || config.HTTPPort > 65535 ||
		(config.SOCKSPort != 0 && config.SOCKSPort == config.HTTPPort) {
		return nil, errors.New("proxy ports must be distinct or 0 for automatic assignment")
	}
	engine := &Engine{
		nodes: make(map[string]outbound.Node), live: make(map[uint64]*tracked),
		summary: []NodeSummary{{Name: Auto, Type: "auto"}, {Name: "DIRECT", Type: "direct"}, {Name: "REJECT", Type: "reject"}},
		ports:   make(map[uint16]bool), spent: make(map[string]bool), health: make(map[string]*health),
		usage: map[string]*counter{"DIRECT": {}}, trigger: make(chan struct{}, 1),
	}
	plans, err := validateSubscriptions(config.Subscriptions)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	engine.plans = append([]Subscription{}, config.Subscriptions...)
	for _, port := range localPorts {
		engine.ports[uint16(port)] = true
	}
	for _, node := range config.Nodes {
		if node.Name == "" || strings.TrimSpace(node.Name) != node.Name || engine.validVia(node.Name) || node.Name == "SELECT" || node.Name == Auto {
			return nil, fmt.Errorf("invalid or duplicate node name %q", node.Name)
		}
		if err := node.Validate(); err != nil {
			return nil, fmt.Errorf("node %q: %w", node.Name, err)
		}
		engine.nodes[node.Name] = node
		engine.order = append(engine.order, node.Name)
		engine.health[node.Name] = &health{}
		engine.usage[node.Name] = &counter{}
		if plan, ok := plans[node.Subscription]; ok && !plan.Usable(now) {
			engine.spent[node.Name] = true
		}
		engine.summary = append(engine.summary, NodeSummary{Name: node.Name, Type: node.Type, Subscription: node.Subscription})
	}
	for index, rule := range config.Rules {
		if !engine.validVia(rule.Via) && rule.Via != "SELECT" {
			return nil, fmt.Errorf("rule %d refers to unknown outbound %q", index+1, rule.Via)
		}
		switch rule.Type {
		case "domain", "domain-suffix":
			rule.Value = normalizeHost(rule.Value)
			if rule.Value == "" || strings.ContainsAny(rule.Value, "/: *") {
				return nil, fmt.Errorf("rule %d needs a domain name", index+1)
			}
		case "ip-cidr":
			prefix, err := netip.ParsePrefix(rule.Value)
			if err != nil {
				return nil, fmt.Errorf("rule %d has an invalid IP prefix", index+1)
			}
			rule.cidr = prefix
		case "match":
			if rule.Value != "" || index != len(config.Rules)-1 {
				return nil, errors.New("match must be the last rule and have no value")
			}
		default:
			return nil, fmt.Errorf("rule %d has unknown type %q", index+1, rule.Type)
		}
		engine.rules = append(engine.rules, rule)
	}
	if err := engine.SetPolicy(Policy{config.Mode, config.Selected}); err != nil {
		return nil, err
	}
	return engine, nil
}

func (engine *Engine) validVia(name string) bool {
	_, exists := engine.nodes[name]
	return exists || name == "DIRECT" || name == "REJECT" || name == Auto
}

func (engine *Engine) SetPolicy(policy Policy) error {
	if policy.Mode != "rule" && policy.Mode != "direct" && policy.Mode != "global" {
		return errors.New("mode must be rule, direct or global")
	}
	if !engine.validVia(policy.Selected) {
		return errors.New("selected outbound does not exist")
	}
	engine.mu.Lock()
	engine.policy = policy
	engine.mu.Unlock()
	return nil
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func (engine *Engine) route(host string, policy Policy) (string, string) {
	switch policy.Mode {
	case "direct":
		return "DIRECT", "direct mode"
	case "global":
		return policy.Selected, "global mode"
	}
	host = normalizeHost(host)
	ip, _ := netip.ParseAddr(host)
	for _, rule := range engine.rules {
		match := false
		switch rule.Type {
		case "domain":
			match = host == rule.Value
		case "domain-suffix":
			match = host == rule.Value || strings.HasSuffix(host, "."+rule.Value)
		case "ip-cidr":
			match = ip.IsValid() && (rule.cidr.Contains(ip) || rule.cidr.Contains(ip.Unmap()))
		case "match":
			match = true
		}
		if match {
			via := rule.Via
			if via == "SELECT" {
				via = policy.Selected
			}
			return via, strings.TrimSpace(rule.Type + " " + rule.Value)
		}
	}
	return "DIRECT", "default"
}

func (engine *Engine) networkDial(ctx context.Context, target string) (net.Conn, error) {
	dialer := net.Dialer{ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
		peer, err := netip.ParseAddrPort(address)
		if err == nil && engine.ports[peer.Port()] && (peer.Addr().Unmap().IsLoopback() || peer.Addr().IsUnspecified()) {
			return errors.New("destination points to this proxy")
		}
		return nil
	}}
	return dialer.DialContext(ctx, "tcp", target)
}

func (engine *Engine) Dial(ctx context.Context, inbound, target string) (net.Conn, error) {
	host, _, err := wire.Split(target)
	if err != nil {
		return nil, err
	}
	engine.mu.Lock()
	engine.sequence++
	via, rule := engine.route(host, engine.policy)
	// Node values are copied under the lock because Reload may swap the map.
	var tries []outbound.Node
	if via == Auto {
		for _, name := range engine.autoOrder(autoAttempts) {
			tries = append(tries, engine.nodes[name])
		}
		rule += " · auto"
		if len(tries) == 0 {
			via = "DIRECT"
		}
	}
	node := engine.nodes[via]
	record := Record{ID: engine.sequence, Target: target, Inbound: inbound, Via: via, Rule: rule, State: "active"}
	engine.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var conn net.Conn
	switch {
	case len(tries) != 0:
		record.Via, conn, err = engine.dialAuto(ctx, tries, target)
	case via == "DIRECT":
		conn, err = engine.networkDial(ctx, target)
	case via == "REJECT":
		err = outbound.ErrRejected
	default:
		attempt, stop := context.WithTimeout(ctx, 8*time.Second)
		conn, err = node.Dial(attempt, target, engine.networkDial)
		stop()
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if err != nil {
		record.State, record.Error = "failed", err.Error()
		if errors.Is(err, outbound.ErrRejected) {
			record.State = "blocked"
		}
		engine.remember(record)
		return nil, err
	}
	tracked := &tracked{Conn: conn, engine: engine, record: record, usage: engine.usage[record.Via]}
	engine.live[record.ID] = tracked
	return tracked, nil
}

func (engine *Engine) remember(record Record) {
	const limit = 150
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
	records = append(records, engine.recent...)
	nodes := make([]NodeSummary, len(engine.summary))
	for index, node := range engine.summary {
		if state := engine.health[node.Name]; state != nil {
			node.Health, node.LatencyMS = state.state, state.latency.Milliseconds()
		}
		if usage := engine.usage[node.Name]; usage != nil {
			node.Sent, node.Recv = usage.sent.Load(), usage.recv.Load()
		}
		node.Spent = engine.spent[node.Name]
		nodes[index] = node
	}
	return Status{engine.policy, nodes, records, len(engine.live), engine.autoChoice(),
		append([]Subscription{}, engine.plans...), engine.revision}
}

type tracked struct {
	net.Conn
	engine     *Engine
	record     Record
	usage      *counter
	sent, recv atomic.Uint64
	once       sync.Once
}

func (conn *tracked) snapshot() Record {
	record := conn.record
	record.Sent, record.Recv = conn.sent.Load(), conn.recv.Load()
	return record
}

func (conn *tracked) Read(data []byte) (int, error) {
	count, err := conn.Conn.Read(data)
	conn.recv.Add(uint64(count))
	if conn.usage != nil {
		conn.usage.recv.Add(uint64(count))
	}
	return count, err
}

func (conn *tracked) Write(data []byte) (int, error) {
	count, err := conn.Conn.Write(data)
	conn.sent.Add(uint64(count))
	if conn.usage != nil {
		conn.usage.sent.Add(uint64(count))
	}
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
		delete(conn.engine.live, record.ID)
		conn.engine.remember(record)
	})
	return err
}

// Reload swaps in a new configuration without dropping live connections.
// Health and traffic counters carry over for nodes that keep their name, and
// the current policy is kept when it is still valid.
func (engine *Engine) Reload(config Config) error {
	engine.mu.Lock()
	ports := make([]int, 0, len(engine.ports))
	for port := range engine.ports {
		ports = append(ports, int(port))
	}
	current := engine.policy
	engine.mu.Unlock()
	next, err := New(config, ports...)
	if err != nil {
		return err
	}
	if next.validVia(current.Selected) {
		next.policy = current
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	for name, state := range engine.health {
		if _, kept := next.health[name]; kept {
			next.health[name] = state
		}
	}
	for name, usage := range engine.usage {
		if _, kept := next.usage[name]; kept {
			next.usage[name] = usage
		}
	}
	engine.policy, engine.nodes, engine.summary, engine.rules = next.policy, next.nodes, next.summary, next.rules
	engine.order, engine.spent, engine.health, engine.usage = next.order, next.spent, next.health, next.usage
	engine.plans = next.plans
	engine.revision++
	engine.CheckNow()
	return nil
}

// Traffic returns cumulative bytes per outbound since the core started.
func (engine *Engine) Traffic() map[string][2]uint64 {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	totals := make(map[string][2]uint64, len(engine.usage))
	for name, usage := range engine.usage {
		totals[name] = [2]uint64{usage.sent.Load(), usage.recv.Load()}
	}
	return totals
}
