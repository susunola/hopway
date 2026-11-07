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
	Name string `json:"name"`
	Type string `json:"type"`
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
}

func New(config Config, localPorts ...int) (*Engine, error) {
	if config.SOCKSPort < 0 || config.SOCKSPort > 65535 || config.HTTPPort < 0 || config.HTTPPort > 65535 ||
		(config.SOCKSPort != 0 && config.SOCKSPort == config.HTTPPort) {
		return nil, errors.New("proxy ports must be distinct or 0 for automatic assignment")
	}
	engine := &Engine{
		nodes: make(map[string]outbound.Node), live: make(map[uint64]*tracked),
		summary: []NodeSummary{{"DIRECT", "direct"}, {"REJECT", "reject"}},
		ports:   make(map[uint16]bool),
	}
	for _, port := range localPorts {
		engine.ports[uint16(port)] = true
	}
	for _, node := range config.Nodes {
		if node.Name == "" || strings.TrimSpace(node.Name) != node.Name || engine.validVia(node.Name) || node.Name == "SELECT" {
			return nil, fmt.Errorf("invalid or duplicate node name %q", node.Name)
		}
		if err := node.Validate(); err != nil {
			return nil, fmt.Errorf("node %q: %w", node.Name, err)
		}
		engine.nodes[node.Name] = node
		engine.summary = append(engine.summary, NodeSummary{node.Name, node.Type})
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
	return exists || name == "DIRECT" || name == "REJECT"
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
	record := Record{ID: engine.sequence, Target: target, Inbound: inbound, Via: via, Rule: rule, State: "active"}
	engine.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var conn net.Conn
	switch via {
	case "DIRECT":
		conn, err = engine.networkDial(ctx, target)
	case "REJECT":
		err = outbound.ErrRejected
	default:
		conn, err = engine.nodes[via].Dial(ctx, target, engine.networkDial)
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
	tracked := &tracked{Conn: conn, engine: engine, record: record}
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
	return Status{engine.policy, engine.summary, records, len(engine.live)}
}

type tracked struct {
	net.Conn
	engine     *Engine
	record     Record
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
		delete(conn.engine.live, record.ID)
		conn.engine.remember(record)
	})
	return err
}
