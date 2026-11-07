package engine

import (
	"context"
	"errors"
	"slices"
	"time"
)

type AutoGroup struct {
	Name       string   `json:"name"`
	ProviderID string   `json:"providerId,omitempty"`
	Nodes      []string `json:"nodes"`
}

type AutoConfig struct {
	Region string      `json:"region"`
	Groups []AutoGroup `json:"groups"`
}

type AutoStatus struct {
	Provider string `json:"provider,omitempty"`
	Node     string `json:"node,omitempty"`
	Probing  bool   `json:"probing"`
}

type autoNode struct {
	latency int64
	passes  int
	fails   int
}

func (node autoNode) viable() bool {
	return node.fails < 2 && (node.passes > 0 || node.latency > 0)
}

type autoState struct {
	config            *AutoConfig
	health            map[string]autoNode
	unavailable       map[int]bool
	activeGroup       int
	activeNode        string
	challenger        string
	challengerWins    int
	probing           bool
	cancel            context.CancelFunc
	orderedCandidates []string
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
		for _, name := range group.Nodes {
			if group.ProviderID != "" && !slices.Contains(providerNodes, name) {
				return errors.New("自动选路引用了不属于该服务商的节点")
			}
			if engine.types[name] == "" || name == "DIRECT" || name == "REJECT" {
				return errors.New("automatic routing references a node outside the running configuration")
			}
			unique[name] = true
		}
	}
	if len(unique) > 256 {
		return errors.New("automatic routing supports up to 256 distinct nodes per region")
	}
	return nil
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
			state.unavailable = engine.unavailableProviders(state.config)
			state.orderedCandidates = state.candidates()
			epoch := engine.networkEpoch.Load()
			probeCtx, cancel := context.WithCancel(ctx)
			state.cancel, state.probing = cancel, true
			engine.mu.Unlock()
			var names []string
			seen := make(map[string]bool)
			for _, group := range state.config.Groups {
				for _, name := range group.Nodes {
					if !seen[name] {
						names = append(names, name)
						seen[name] = true
					}
				}
			}
			measurements := make([]ProbeResult, 0, len(names))
			err := engine.probeNodes(probeCtx, names, func(result ProbeResult) error {
				measurements = append(measurements, result)
				return nil
			})
			cancel()
			engine.mu.Lock()
			if engine.auto == state {
				state.probing, state.cancel = false, nil
				if err == nil && engine.networkEpoch.Load() == epoch {
					state.apply(measurements)
				}
			}
			engine.mu.Unlock()
		} else {
			engine.mu.Unlock()
		}

		timer := time.NewTimer(60 * time.Second)
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
		if !node.viable() || (recovering && node.passes < 2) {
			continue
		}
		if best == "" || node.latency < state.health[best].latency {
			best = name
		}
	}
	return best
}

func (state *autoState) apply(results []ProbeResult) {
	measured := false
	for _, result := range results {
		if result.Inconclusive {
			continue
		}
		measured = true
		node := state.health[result.Name]
		if result.Failure == "" {
			if node.latency == 0 {
				node.latency = result.Milliseconds
			} else {
				node.latency = (node.latency*2 + result.Milliseconds) / 3
			}
			node.fails, node.passes = 0, min(node.passes+1, 2)
		} else {
			node.passes, node.fails = 0, min(node.fails+1, 2)
		}
		state.health[result.Name] = node
	}
	if !measured {
		return
	}
	defer func() { state.orderedCandidates = state.candidates() }()
	activeHealthy := state.activeNode != "" && !state.unavailable[state.activeGroup] && state.health[state.activeNode].viable()
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
		if best == state.activeNode || active.latency-state.health[best].latency < max(50, active.latency/5) {
			state.challenger, state.challengerWins = "", 0
			return
		}
		if state.challenger != best {
			state.challenger, state.challengerWins = best, 0
		}
		state.challengerWins++
		if state.challengerWins >= 2 {
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
				case node.viable():
					return node.latency
				case !measured || node.fails < 2:
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
			usage := sub.Usage
			expired := usage.ExpiresAt > 0 && now.Unix() >= usage.ExpiresAt
			if date, err := time.ParseInLocation(time.DateOnly, usage.ExpiryDate, now.Location()); err == nil {
				expired = expired || !now.Before(date.AddDate(0, 0, 1))
			}
			exhausted := usage.Used != nil && usage.Total != nil && *usage.Total > 0 && *usage.Used >= *usage.Total
			blocked[index] = expired || exhausted
		}
	}
	return blocked
}
