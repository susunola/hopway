package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mac-proxy/internal/outbound"
)

// Auto is the virtual outbound that picks the first healthy node in priority
// order (config order) and falls back to the next one when a node fails.
const Auto = "AUTO"

const (
	probeTarget  = "www.gstatic.com:80"
	probeRequest = "GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nUser-Agent: HopWay\r\nConnection: close\r\n\r\n"
	autoAttempts = 3
)

// Subscription records where imported nodes came from and the plan usage the
// provider reported in its Subscription-Userinfo header.
type Subscription struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Upload   int64  `json:"upload,omitempty"`
	Download int64  `json:"download,omitempty"`
	Total    int64  `json:"total,omitempty"`
	Expire   int64  `json:"expire,omitempty"`
	Updated  int64  `json:"updated,omitempty"`
}

// Usable reports whether the plan still has traffic and time left. Plans that
// report no limits count as usable.
func (plan Subscription) Usable(now time.Time) bool {
	if plan.Total > 0 && plan.Upload+plan.Download >= plan.Total {
		return false
	}
	return plan.Expire <= 0 || now.Unix() < plan.Expire
}

func validateSubscriptions(plans []Subscription) (map[string]Subscription, error) {
	byName := make(map[string]Subscription, len(plans))
	for _, plan := range plans {
		if plan.Name == "" || strings.TrimSpace(plan.Name) != plan.Name {
			return nil, errors.New("subscription needs a name")
		}
		if _, exists := byName[plan.Name]; exists {
			return nil, fmt.Errorf("duplicate subscription %q", plan.Name)
		}
		source, err := url.Parse(plan.URL)
		if err != nil || (source.Scheme != "https" && source.Scheme != "http") || source.Hostname() == "" {
			return nil, fmt.Errorf("subscription %q needs an http(s) URL", plan.Name)
		}
		byName[plan.Name] = plan
	}
	return byName, nil
}

type health struct {
	state    string // "", "ok" or "down"
	latency  time.Duration
	checked  time.Time
	lastOK   time.Time
	failures int // consecutive failed probes
}

// probeFailuresToDown is how many failed probes in a row take a node down. A
// confirmed connection failure takes it down at once.
const probeFailuresToDown = 2

type counter struct{ sent, recv atomic.Uint64 }

// candidates lists nodes in priority order. Nodes whose plan is used up or
// expired are skipped unless nothing else is left. The caller holds mu.
func (engine *Engine) candidates() []string {
	var usable, spent []string
	for _, name := range engine.order {
		if engine.spent[name] {
			spent = append(spent, name)
		} else {
			usable = append(usable, name)
		}
	}
	if len(usable) == 0 {
		return spent
	}
	return usable
}

// autoOrder returns the nodes to try for a new connection: nodes not known to
// be down first, in priority order, then the rest. The caller holds mu.
func (engine *Engine) autoOrder(limit int) []string {
	var first, later []string
	for _, name := range engine.candidates() {
		if engine.health[name].state == "down" {
			later = append(later, name)
		} else {
			first = append(first, name)
		}
	}
	// When nodes are down, try the one that worked most recently first.
	sort.SliceStable(later, func(i, j int) bool {
		return engine.health[later[i]].lastOK.After(engine.health[later[j]].lastOK)
	})
	order := append(first, later...)
	if len(order) > limit {
		order = order[:limit]
	}
	return order
}

// autoChoice is the node AUTO currently resolves to. The caller holds mu.
func (engine *Engine) autoChoice() string {
	if order := engine.autoOrder(1); len(order) == 1 {
		return order[0]
	}
	return "DIRECT"
}

// mark records a confirmed result for a node. The caller holds mu.
func (engine *Engine) mark(name string, ok bool, latency time.Duration) {
	state := engine.health[name]
	if state == nil {
		return
	}
	state.checked = time.Now()
	if ok {
		state.state, state.lastOK, state.failures = "ok", state.checked, 0
		if latency > 0 {
			state.latency = latency
		}
		return
	}
	state.state, state.latency = "down", 0
}

// markProbe records a health-check result; one failed probe is not enough to
// take a node down. The caller holds mu.
func (engine *Engine) markProbe(name string, ok bool, latency time.Duration) {
	state := engine.health[name]
	if state == nil {
		return
	}
	if ok {
		engine.mark(name, true, latency)
		return
	}
	state.checked = time.Now()
	if state.failures++; state.failures >= probeFailuresToDown {
		state.state, state.latency = "down", 0
	}
}

// dialAuto tries the AUTO candidates in order. A node is only marked down when
// a later node reaches the same target, so an unreachable target does not
// take every node offline.
func (engine *Engine) dialAuto(ctx context.Context, tries []outbound.Node, target string) (string, net.Conn, error) {
	var failed []string
	var lastErr error
	for _, node := range tries {
		name := node.Name
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := node.Dial(attempt, target, engine.networkDial)
		cancel()
		if err == nil {
			engine.mu.Lock()
			for _, bad := range failed {
				engine.mark(bad, false, 0)
			}
			engine.mark(name, true, 0)
			engine.mu.Unlock()
			if len(failed) != 0 {
				engine.CheckNow()
			}
			return name, conn, nil
		}
		failed, lastErr = append(failed, name), err
		if ctx.Err() != nil {
			break
		}
	}
	if len(tries) == 0 {
		return "DIRECT", nil, errors.New("no outbound node available")
	}
	return failed[len(failed)-1], nil, lastErr
}

// CheckNow asks the health checker to run a round as soon as possible.
func (engine *Engine) CheckNow() {
	select {
	case engine.trigger <- struct{}{}:
	default:
	}
}

// RunHealthChecks probes every node now, then every interval or when CheckNow
// is called, until ctx is done.
func (engine *Engine) RunHealthChecks(ctx context.Context, interval time.Duration) {
	for {
		engine.Probe(ctx)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-engine.trigger:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// Probe measures each node by fetching generate_204 through it.
func (engine *Engine) Probe(ctx context.Context) {
	engine.mu.Lock()
	nodes := make([]outbound.Node, 0, len(engine.order))
	for _, name := range engine.order {
		nodes = append(nodes, engine.nodes[name])
	}
	engine.mu.Unlock()
	limit := make(chan struct{}, 8)
	var group sync.WaitGroup
	for _, node := range nodes {
		group.Add(1)
		limit <- struct{}{}
		go func() {
			defer group.Done()
			defer func() { <-limit }()
			latency, err := engine.probe(ctx, node)
			if ctx.Err() != nil {
				return
			}
			engine.mu.Lock()
			engine.markProbe(node.Name, err == nil, latency)
			engine.mu.Unlock()
		}()
	}
	group.Wait()
}

func (engine *Engine) probe(ctx context.Context, node outbound.Node) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := node.Dial(ctx, probeTarget, engine.networkDial)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if _, err := io.WriteString(conn, probeRequest); err != nil {
		return 0, err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/1.") || (fields[1] != "204" && fields[1] != "200") {
		return 0, errors.New("unexpected probe reply")
	}
	return time.Since(start), nil
}
