package profile

import (
	"fmt"
	"slices"

	"mac-proxy/internal/engine"
)

type referenceTarget struct {
	name    string
	ruleSet bool
}

type referenceKey struct {
	kind   string
	group  string
	rule   engine.Rule
	target referenceTarget
}

type unresolvedReference struct {
	referenceKey
	index int
}

func (ref unresolvedReference) Error() string {
	switch ref.kind {
	case "outbound":
		return fmt.Sprintf("选定出站 %q 不存在", ref.target.name)
	case "member":
		return fmt.Sprintf("策略组 %q 引用了不存在的成员 %q", ref.group, ref.target.name)
	case "selection":
		return fmt.Sprintf("策略组 %q 的选定项 %q 不在成员列表中", ref.group, ref.target.name)
	case "empty group":
		return fmt.Sprintf("策略组 %q 没有成员", ref.group)
	case "rule set":
		return fmt.Sprintf("第 %d 条规则引用了不存在的规则集 %q", ref.index, ref.target.name)
	default:
		return fmt.Sprintf("第 %d 条规则引用了不存在的出站 %q", ref.index, ref.target.name)
	}
}

// Visit user-authored references with their current resolution status. The
// effective catalog includes the same names the subscription merge assigned.
func visitReferences(user, merged engine.Config, visit func(unresolvedReference, bool)) {
	outbounds := map[string]bool{"DIRECT": true, "REJECT": true}
	for _, node := range merged.Nodes {
		outbounds[node.Name] = true
	}
	for _, group := range merged.Groups {
		outbounds[group.Name] = true
	}
	sets := make(map[string]bool, len(merged.RuleSets))
	for _, set := range merged.RuleSets {
		sets[set.Name] = true
	}
	visit(unresolvedReference{referenceKey: referenceKey{kind: "outbound", target: referenceTarget{name: user.Selected}}}, outbounds[user.Selected])
	for _, group := range user.Groups {
		if len(group.Members) == 0 {
			visit(unresolvedReference{referenceKey: referenceKey{kind: "empty group", group: group.Name}}, false)
		}
		for _, name := range group.Members {
			key := referenceKey{kind: "member", group: group.Name, target: referenceTarget{name: name}}
			visit(unresolvedReference{referenceKey: key}, outbounds[name])
		}
		if group.Selected != "" {
			key := referenceKey{kind: "selection", group: group.Name, target: referenceTarget{name: group.Selected}}
			visit(unresolvedReference{referenceKey: key}, slices.Contains(group.Members, group.Selected))
		}
	}
	for i, rule := range user.Rules {
		key := referenceKey{kind: "rule", rule: rule, target: referenceTarget{name: rule.Via}}
		visit(unresolvedReference{referenceKey: key, index: i + 1}, rule.Via == "SELECT" || outbounds[rule.Via])
		if rule.Type == engine.RuleRuleSet {
			key = referenceKey{kind: "rule set", rule: rule, target: referenceTarget{name: rule.Value, ruleSet: true}}
			visit(unresolvedReference{referenceKey: key, index: i + 1}, sets[rule.Value])
		}
	}
}

func validateReferences(candidate, merged, previous engine.Config, dataDir, stagedName string) error {
	var missing []unresolvedReference
	visitReferences(candidate, merged, func(ref unresolvedReference, exists bool) {
		if !exists {
			missing = append(missing, ref)
		}
	})
	if len(missing) == 0 {
		return nil
	}
	active := make(map[string]engine.Subscription, len(candidate.Subscriptions))
	for _, sub := range candidate.Subscriptions {
		if !sub.Paused {
			active[sub.Key()] = sub
		}
	}
	displaced := make(map[string]bool)
	snapshots := make(map[string]*Snapshot, len(previous.Subscriptions))
	for _, sub := range previous.Subscriptions {
		if next, ok := active[sub.Key()]; !ok || next.URL != sub.URL || next.SnapshotKey != sub.SnapshotKey ||
			(stagedName != "" && next.Name == stagedName) {
			displaced[sub.Key()] = true
		}
		if snapshot, err := LoadSnapshot(dataDir, sub); err == nil {
			snapshots[sub.Name] = snapshot
		}
	}
	owners := make(map[referenceTarget]string)
	oldMerged, _ := merge(previous, snapshots, owners)
	allowed := make(map[referenceKey]int)
	visitReferences(previous, oldMerged, func(ref unresolvedReference, exists bool) {
		if !exists || (ref.kind != "selection" && displaced[owners[ref.target]]) {
			allowed[ref.referenceKey]++
		}
	})
	for _, ref := range missing {
		if allowed[ref.referenceKey] == 0 {
			return ref
		}
		allowed[ref.referenceKey]--
	}
	return nil
}

// An unchanged user-authored rule or group member still refers to its
// original provider. A display-name collision must not rebind it on reload.
func validateReferenceBindings(previous, candidate Loaded) error {
	bindings := make(map[referenceKey]string)
	visitReferences(previous.User, previous.Merged, func(ref unresolvedReference, exists bool) {
		if exists && !ref.target.ruleSet {
			bindings[ref.referenceKey] = previous.Merged.OutboundIDs[ref.target.name]
		}
	})
	var err error
	visitReferences(candidate.User, candidate.Merged, func(ref unresolvedReference, exists bool) {
		if old := bindings[ref.referenceKey]; err == nil && exists && old != "" &&
			old != candidate.Merged.OutboundIDs[ref.target.name] {
			err = fmt.Errorf("出站 %q 的订阅来源已变化，请更新引用后重新加载", ref.target.name)
		}
	})
	return err
}
