package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

type AutoGroup struct {
	Name       string   `json:"name"`
	ProviderID string   `json:"providerId,omitempty"`
	Nodes      []string `json:"nodes"`
	NodeIDs    []string `json:"nodeIds,omitempty"`
}

type AutoConfig struct {
	Region string      `json:"region"`
	Groups []AutoGroup `json:"groups"`
}

// AutoSwitchConfig tunes provider and node selection in automatic routing mode.
type AutoSwitchConfig struct {
	GainMS            int `json:"gainMs,omitempty"`
	GainPercent       int `json:"gainPercent,omitempty"`
	Confirmations     int `json:"confirmations,omitempty"`
	FailoverFailures  int `json:"failoverFailures,omitempty"`
	RecoverySuccesses int `json:"recoverySuccesses,omitempty"`
}

func (config AutoSwitchConfig) effective() (AutoSwitchConfig, error) {
	for _, field := range []struct {
		name          string
		value         *int
		fallback, max int
	}{
		{"gainMs", &config.GainMS, 50, 2000},
		{"gainPercent", &config.GainPercent, 20, 95},
		{"confirmations", &config.Confirmations, 2, 10},
		{"failoverFailures", &config.FailoverFailures, 2, 10},
		{"recoverySuccesses", &config.RecoverySuccesses, 2, 10},
	} {
		if *field.value == 0 {
			*field.value = field.fallback
		}
		if *field.value < 1 || *field.value > field.max {
			return AutoSwitchConfig{}, fmt.Errorf("autoSwitch.%s must be between 1 and %d", field.name, field.max)
		}
	}
	return config, nil
}

type AutoStatus struct {
	Provider   string `json:"provider,omitempty"`
	Node       string `json:"node,omitempty"`
	Probing    bool   `json:"probing"`
	Candidates int    `json:"candidates,omitempty"`
}

type autoNode struct {
	latency int64
	passes  int
	fails   int
}

func (node autoNode) viable(failures int) bool {
	return node.fails < failures && (node.passes > 0 || node.latency > 0)
}

type autoState struct {
	config            *AutoConfig
	switching         AutoSwitchConfig
	health            map[string]autoNode
	unavailable       map[int]bool
	activeGroup       int
	activeNode        string
	challenger        string
	challengerWins    int
	probing           bool
	cancel            context.CancelFunc
	orderedCandidates []string
	fastest           bool
	eligible          []string
	ready             chan struct{}
}

func (state *autoState) finishFirstProbe() {
	if state.ready != nil {
		close(state.ready)
		state.ready = nil
	}
}

// fastestNodes contains only concrete proxy nodes, even if a subscription's
// strategy group lists DIRECT. Paused or exhausted providers are excluded.
func (engine *Engine) fastestNodes() []string {
	blocked := make(map[string]bool)
	now := time.Now()
	for _, sub := range engine.subscriptions {
		if sub.Paused || providerUnavailable(sub, now) {
			for _, name := range sub.Nodes {
				blocked[name] = true
			}
		}
	}
	var names []string
	for _, name := range engine.order {
		if name != "DIRECT" && name != "REJECT" && engine.types[name] != "" && !blocked[name] {
			names = append(names, name)
		}
	}
	return names
}

// rankFastest runs under engine.mu. Use comparable results from the primary
// target first, and use measurements from the fallback when necessary.
func (engine *Engine) rankFastest(state *autoState) {
	var verified []string
	for _, name := range state.eligible {
		if health := engine.health[name]; health != nil && health.alive && health.target != "" {
			verified = append(verified, name)
		}
	}
	slices.SortStableFunc(verified, func(a, b string) int {
		left, right := engine.health[a], engine.health[b]
		if left.target != right.target {
			// Primary and fallback have different response latencies.
			if left.target == engine.probeHost {
				return -1
			}
			if right.target == engine.probeHost {
				return 1
			}
		}
		return cmp.Compare(left.latency, right.latency)
	})
	state.activeNode = ""
	if len(verified) > 0 {
		state.activeNode = verified[0]
		state.finishFirstProbe()
	}
	state.orderedCandidates = verified[:min(len(verified), engine.attempts)]
}

func (engine *Engine) validateAuto(config *AutoConfig) error {
	if config == nil || config.Region == "" || len(config.Groups) == 0 || len(config.Groups) > 64 {
		return errors.New("automatic routing needs a region and at least one provider")
	}
	unique := make(map[string]bool)
	for _, group := range config.Groups {
		if group.Name == "" || len(group.Nodes) == 0 || len(group.Nodes) > 256 {
			return errors.New("automatic routing provider has no usable nodes or too many nodes")
		}
		var providerNodes []string
		if group.ProviderID != "" {
			for _, sub := range engine.subscriptions {
				if sub.Key() == group.ProviderID && !sub.Paused {
					providerNodes = sub.Nodes
					break
				}
			}
		}
		for i, name := range group.Nodes {
			if group.ProviderID != "" && !slices.Contains(providerNodes, name) {
				return errors.New("自动选路引用了不属于该服务商的节点")
			}
			if engine.types[name] == "" || name == "DIRECT" || name == "REJECT" {
				return errors.New("automatic routing references a node outside the running configuration")
			}
			if len(group.NodeIDs) != 0 && (len(group.NodeIDs) != len(group.Nodes) || group.NodeIDs[i] != engine.outboundIDs[name]) {
				return errors.New("自动选路引用了已变化的节点")
			}
			unique[name] = true
		}
	}
	if len(unique) > 256 {
		return errors.New("automatic routing supports up to 256 distinct nodes per region")
	}
	return nil
}

// BindAutoNodes fills identities for new or legacy automatic routes. Existing
// identities survive a refresh that temporarily removes a provider.
func (engine *Engine) BindAutoNodes(policy Policy) Policy {
	if policy.Mode != "auto" || policy.Auto == nil {
		return policy
	}
	config := *policy.Auto
	config.Groups = slices.Clone(config.Groups)
	for i := range config.Groups {
		group := &config.Groups[i]
		if len(group.NodeIDs) == len(group.Nodes) {
			continue
		}
		group.NodeIDs = make([]string, len(group.Nodes))
		for j, name := range group.Nodes {
			if group.ProviderID != "" {
				var belongs bool
				for _, sub := range engine.subscriptions {
					if sub.Key() == group.ProviderID && slices.Contains(sub.Nodes, name) {
						belongs = true
						break
					}
				}
				if !belongs {
					continue
				}
			}
			group.NodeIDs[j] = engine.outboundIDs[name]
		}
	}
	policy.Auto = &config
	return policy
}

func (engine *Engine) MonitorAuto(ctx context.Context) {
	for {
		engine.mu.Lock()
		state := engine.auto
		select {
		case <-engine.autoWake:
		default:
		}
		if state != nil {
			var names []string
			if state.fastest {
				state.eligible = engine.fastestNodes()
				engine.rankFastest(state)
				names = state.eligible
			} else {
				state.unavailable = engine.unavailableProviders(state.config)
				state.orderedCandidates = state.candidates()
				seen := make(map[string]bool)
				for _, group := range state.config.Groups {
					for _, name := range group.Nodes {
						if !seen[name] {
							names = append(names, name)
							seen[name] = true
						}
					}
				}
			}
			epoch := engine.networkEpoch.Load()
			probeCtx, cancel := context.WithCancel(ctx)
			state.cancel, state.probing = cancel, true
			engine.mu.Unlock()
			var measurements []ProbeResult
			var emit func(ProbeResult) error
			if !state.fastest {
				measurements = make([]ProbeResult, 0, len(names))
				emit = func(result ProbeResult) error {
					measurements = append(measurements, result)
					return nil
				}
			}
			err := engine.probeNodes(probeCtx, names, emit)
			cancel()
			engine.mu.Lock()
			if engine.auto == state {
				state.probing, state.cancel = false, nil
				if err == nil && engine.networkEpoch.Load() == epoch {
					if state.fastest {
						state.finishFirstProbe()
					} else {
						state.apply(measurements)
					}
				}
			}
			engine.mu.Unlock()
		} else {
			engine.mu.Unlock()
		}

		timer := time.NewTimer(engine.performance.autoRouteInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-engine.autoWake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (state *autoState) bestNode(group int, recovering bool) string {
	best := ""
	if state.unavailable[group] {
		return ""
	}
	for _, name := range state.config.Groups[group].Nodes {
		node := state.health[name]
		if !node.viable(state.switching.FailoverFailures) || (recovering && node.passes < state.switching.RecoverySuccesses) {
			continue
		}
		if best == "" || node.latency < state.health[best].latency {
			best = name
		}
	}
	return best
}

func (state *autoState) apply(results []ProbeResult) {
	measured := make(map[string]bool, len(results))
	for _, result := range results {
		if result.Inconclusive {
			continue
		}
		measured[result.Name] = result.Failure == ""
		node := state.health[result.Name]
		if result.Failure == "" {
			if node.latency == 0 {
				node.latency = result.Milliseconds
			} else {
				node.latency = (node.latency*2 + result.Milliseconds) / 3
			}
			node.fails, node.passes = 0, min(node.passes+1, state.switching.RecoverySuccesses)
		} else {
			node.passes, node.fails = 0, min(node.fails+1, state.switching.FailoverFailures)
		}
		state.health[result.Name] = node
	}
	if len(measured) == 0 {
		return
	}
	defer func() { state.orderedCandidates = state.candidates() }()
	activeHealthy := state.activeNode != "" && !state.unavailable[state.activeGroup] &&
		state.health[state.activeNode].viable(state.switching.FailoverFailures)
	for group := range state.config.Groups {
		if activeHealthy && group > state.activeGroup {
			break
		}
		best := state.bestNode(group, activeHealthy && group < state.activeGroup)
		if best == "" {
			continue
		}
		if !activeHealthy || group != state.activeGroup {
			state.activeGroup, state.activeNode = group, best
			state.challenger, state.challengerWins = "", 0
			return
		}

		active := state.health[state.activeNode]
		gain := max(int64(state.switching.GainMS), active.latency*int64(state.switching.GainPercent)/100)
		if best == state.activeNode || active.latency-state.health[best].latency < gain {
			state.challenger, state.challengerWins = "", 0
			return
		}
		activeOK, activeMeasured := measured[state.activeNode]
		bestOK, bestMeasured := measured[best]
		if (activeMeasured && !activeOK) || (bestMeasured && !bestOK) {
			state.challenger, state.challengerWins = "", 0
			return
		}
		if !activeOK || !bestOK {
			return
		}
		if state.challenger != best {
			state.challenger, state.challengerWins = best, 0
		}
		state.challengerWins++
		if state.challengerWins >= state.switching.Confirmations {
			state.activeNode = best
			state.challenger, state.challengerWins = "", 0
		}
		return
	}
	state.activeGroup, state.activeNode = -1, ""
	state.challenger, state.challengerWins = "", 0
}

func (state *autoState) candidates() []string {
	var names []string
	add := func(name string) {
		if name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	active := max(0, state.activeGroup)
	if !state.unavailable[active] {
		add(state.activeNode)
	}
	ordered := func(index int) []string {
		if state.unavailable[index] {
			return nil
		}
		nodes := slices.Clone(state.config.Groups[index].Nodes)
		slices.SortStableFunc(nodes, func(a, b string) int {
			rank := func(name string) int64 {
				node, measured := state.health[name]
				switch {
				case node.viable(state.switching.FailoverFailures):
					return node.latency
				case !measured || node.fails < state.switching.FailoverFailures:
					return 1 << 30
				default:
					return 1 << 31
				}
			}
			if rank(a) < rank(b) {
				return -1
			}
			if rank(a) > rank(b) {
				return 1
			}
			return 0
		})
		return nodes
	}
	for _, name := range ordered(active) {
		add(name)
		if len(names) == 2 {
			break
		}
	}
	for index := range state.config.Groups {
		if index == active {
			continue
		}
		for _, name := range ordered(index) {
			if !slices.Contains(names, name) {
				add(name)
				break
			}
		}
		if len(names) == 3 {
			break
		}
	}
	return names
}

func (engine *Engine) unavailableProviders(config *AutoConfig) map[int]bool {
	blocked := map[int]bool{}
	now := time.Now()
	for index, group := range config.Groups {
		if group.ProviderID == "" {
			continue
		}
		for _, sub := range engine.subscriptions {
			if sub.Key() != group.ProviderID || sub.Usage == nil {
				continue
			}
			blocked[index] = providerUnavailable(sub, now)
		}
	}
	return blocked
}

func providerUnavailable(sub Subscription, now time.Time) bool {
	usage := sub.Usage
	if usage == nil {
		return false
	}
	expired := usage.ExpiresAt > 0 && now.Unix() >= usage.ExpiresAt
	if date, err := time.ParseInLocation(time.DateOnly, usage.ExpiryDate, now.Location()); err == nil {
		expired = expired || !now.Before(date.AddDate(0, 0, 1))
	}
	exhausted := usage.Used != nil && usage.Total != nil && *usage.Total > 0 && *usage.Used >= *usage.Total
	return expired || exhausted
}
