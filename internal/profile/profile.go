// Package profile assembles the configuration the engine runs: the user's
// own file, merged with the latest snapshot of each subscription, falling
// back to the last configuration that worked when the file is broken.
package profile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mac-proxy/internal/engine"
	"mac-proxy/internal/importer"
	"mac-proxy/internal/outbound"
)

// Snapshot is what one subscription contributed at its last refresh.
type Snapshot struct {
	Usage   *engine.SubscriptionUsage `json:"usage,omitempty"`
	Samples []engine.UsageSample      `json:"usageSamples,omitempty"`

	Updated    int64                `json:"updated"` // last routing update, Unix ms
	Checked    int64                `json:"checked,omitempty"`
	Validators *importer.Validators `json:"validators,omitempty"`
	Nodes      []outbound.Node      `json:"nodes"`
	Groups     []engine.Group       `json:"groups,omitempty"`
	Rules      []engine.Rule        `json:"rules,omitempty"`
	RuleSets   []engine.RuleSet     `json:"ruleSets,omitempty"`
	Health     *engine.Health       `json:"health,omitempty"`
	Skipped    int                  `json:"skipped,omitempty"`
	Notes      []string             `json:"notes,omitempty"`
}

func (snapshot *Snapshot) CheckedAt() int64 {
	return max(snapshot.Checked, snapshot.Updated)
}

func subscriptionCacheStem(dataDir string, sub engine.Subscription) string {
	sum := sha256.Sum256([]byte(sub.URL))
	return filepath.Join(dataDir, "subscriptions", hex.EncodeToString(sum[:8]))
}

func SnapshotPath(dataDir string, sub engine.Subscription) string {
	stem := subscriptionCacheStem(dataDir, sub)
	if sub.SnapshotKey != "" && validSnapshotKey(sub.SnapshotKey) {
		stem += "-" + sub.SnapshotKey
	}
	return stem + ".json"
}

func validSnapshotKey(key string) bool {
	if len(key) != 32 {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}

func LoadSnapshot(dataDir string, sub engine.Subscription) (*Snapshot, error) {
	data, err := os.ReadFile(SnapshotPath(dataDir, sub))
	if err != nil {
		return nil, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func SaveSnapshot(dataDir string, sub engine.Subscription, snapshot *Snapshot) error {
	release, err := LockWrites(dataDir)
	if err != nil {
		return err
	}
	defer release()
	return saveSnapshot(context.Background(), dataDir, sub, snapshot)
}

func saveSnapshot(ctx context.Context, dataDir string, sub engine.Subscription, snapshot *Snapshot) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return engine.WriteAtomicChecked(SnapshotPath(dataDir, sub), data, ctx.Err)
}

// Merge layers subscription snapshots under the user's configuration:
// the user's nodes, groups and rules come first and win name clashes, the
// user's final "match" rule (if any) stays last, and references that no
// snapshot provides yet are dropped with a warning instead of failing.
func Merge(user engine.Config, snapshots map[string]*Snapshot) (engine.Config, []string) {
	return merge(user, snapshots, nil)
}

func merge(user engine.Config, snapshots map[string]*Snapshot, owners map[referenceTarget]string) (engine.Config, []string) {
	merged := user
	merged.OutboundIDs = make(map[string]string)
	merged.Subscriptions = append([]engine.Subscription(nil), user.Subscriptions...)
	// Before subscriptions used snapshots, their nodes were embedded in the
	// user file. Keep them as a fallback until all their owners have snapshots.
	oldOwned := map[string]bool{}
	retain := map[string]bool{}
	legacyOwners := map[string]string{}
	for _, name := range user.SubscriptionNodes {
		oldOwned[name] = true
	}
	for _, sub := range user.Subscriptions {
		for _, name := range sub.Nodes {
			oldOwned[name] = true
			if !sub.Paused && snapshots[sub.Name] == nil {
				retain[name] = true
				legacyOwners[name] = sub.Key()
			}
		}
	}
	merged.Nodes = nil
	for _, node := range user.Nodes {
		if !oldOwned[node.Name] || retain[node.Name] {
			merged.Nodes = append(merged.Nodes, node)
			if key := legacyOwners[node.Name]; key != "" {
				merged.OutboundIDs[node.Name] = engine.SourceOutboundID(key, node.Name, false)
				if owners != nil {
					owners[referenceTarget{name: node.Name}] = key
				}
			}
		}
	}
	merged.Groups = append([]engine.Group(nil), user.Groups...)
	merged.RuleSets = append([]engine.RuleSet(nil), user.RuleSets...)
	var warnings []string
	taken := map[string]bool{"DIRECT": true, "REJECT": true, "SELECT": true}
	for _, node := range merged.Nodes {
		taken[node.Name] = true
	}
	for _, group := range user.Groups {
		taken[group.Name] = true
	}
	setNames := map[string]bool{}
	for _, set := range user.RuleSets {
		setNames[set.Name] = true
	}
	userRules := append([]engine.Rule(nil), user.Rules...)
	var final *engine.Rule
	if n := len(userRules); n > 0 && userRules[n-1].Type == engine.RuleMatch {
		last := userRules[n-1] // a copy: appending below reuses the slot
		final = &last
		userRules = userRules[: n-1 : n-1]
	}
	var subRules []engine.Rule
	var subFinal *engine.Rule
	firstGroup := ""
	for i, sub := range user.Subscriptions {
		snapshot := snapshots[sub.Name]
		if sub.Paused {
			merged.Subscriptions[i].Nodes = nil
			if snapshot != nil && snapshot.Usage != nil {
				merged.Subscriptions[i].Usage, merged.Subscriptions[i].UsageSamples = snapshot.Usage, snapshot.Samples
			}
			continue
		}
		if snapshot == nil {
			continue
		}
		key := sub.Key()
		merged.Subscriptions[i].Nodes = nil
		if snapshot.Usage != nil {
			merged.Subscriptions[i].Usage = snapshot.Usage
			merged.Subscriptions[i].UsageSamples = snapshot.Samples
		}
		rename := map[string]string{}
		firstNode := len(merged.Nodes)
		renamedNodes := false
		unique := func(name string, used map[string]bool) string {
			candidate := name
			for i := 2; used[candidate]; i++ {
				candidate = fmt.Sprintf("%s (%s %d)", name, sub.Name, i)
			}
			used[candidate] = true
			return candidate
		}
		for _, node := range snapshot.Nodes {
			original := node.Name
			node.Name = unique(original, taken)
			rename[original] = node.Name
			renamedNodes = renamedNodes || node.Name != original
			merged.Nodes = append(merged.Nodes, node)
			merged.OutboundIDs[node.Name] = engine.SourceOutboundID(key, original, false)
			if owners != nil {
				owners[referenceTarget{name: node.Name}] = key
			}
			merged.Subscriptions[i].Nodes = append(merged.Subscriptions[i].Nodes, node.Name)
		}
		if renamedNodes {
			for j := firstNode; j < len(merged.Nodes); j++ {
				remapDetour(&merged.Nodes[j], rename)
			}
		}
		for _, group := range snapshot.Groups {
			rename[group.Name] = unique(group.Name, taken)
			merged.OutboundIDs[rename[group.Name]] = engine.SourceOutboundID(key, group.Name, true)
			if owners != nil {
				owners[referenceTarget{name: rename[group.Name]}] = key
			}
		}
		mapName := func(name string) string {
			if mapped, ok := rename[name]; ok {
				return mapped
			}
			return name
		}
		for _, group := range snapshot.Groups {
			group.Name = rename[group.Name]
			members := make([]string, len(group.Members))
			for i, member := range group.Members {
				members[i] = mapName(member)
			}
			group.Members = members
			if group.Selected != "" {
				group.Selected = mapName(group.Selected)
			}
			merged.Groups = append(merged.Groups, group)
			if firstGroup == "" {
				firstGroup = group.Name
			}
		}
		setRename := map[string]string{}
		for _, set := range snapshot.RuleSets {
			original := set.Name
			set.Name = unique(original, setNames)
			setRename[original] = set.Name
			merged.RuleSets = append(merged.RuleSets, set)
			if owners != nil {
				owners[referenceTarget{ruleSet: true, name: set.Name}] = key
			}
		}
		for _, rule := range snapshot.Rules {
			rule.Via = mapName(rule.Via)
			if rule.Type == engine.RuleRuleSet {
				rule.Value = setRename[rule.Value]
			}
			if rule.Type == engine.RuleMatch {
				if subFinal == nil {
					r := rule
					subFinal = &r
				}
				continue
			}
			subRules = append(subRules, rule)
		}
		if merged.Health == nil && snapshot.Health != nil {
			merged.Health = snapshot.Health
		}
	}
	merged.Rules = append(userRules, subRules...)
	if final == nil {
		final = subFinal
	}
	if final != nil {
		merged.Rules = append(merged.Rules, *final)
	}
	if len(user.Nodes) == 0 && len(user.Groups) == 0 && user.Selected == "DIRECT" {
		// A configuration made only of subscriptions: select what they offer.
		if firstGroup != "" {
			merged.Selected = firstGroup
		} else if len(merged.Nodes) != 0 {
			merged.Selected = merged.Nodes[0].Name
		}
	}
	warnings = append(warnings, applyGroupMembers(&merged)...)
	warnings = append(warnings, prune(&merged)...)
	return merged, warnings
}

// Overrides can add nodes and reorder existing subgroup links. Keeping
// subgroup links within the source graph avoids cycles after a refresh.
func applyGroupMembers(config *engine.Config) []string {
	if len(config.GroupMembers) == 0 {
		return nil
	}
	names := map[string]string{"DIRECT": "DIRECT", "REJECT": "REJECT"}
	groupNames := make(map[string]bool, len(config.Groups))
	for _, node := range config.Nodes {
		names[config.OutboundID(node.Name, false)] = node.Name
	}
	for _, group := range config.Groups {
		names[config.OutboundID(group.Name, true)] = group.Name
		groupNames[group.Name] = true
	}
	var warnings []string
	for i := range config.Groups {
		group := &config.Groups[i]
		members, customized := config.GroupMembers[config.OutboundID(group.Name, true)]
		if !customized {
			continue
		}
		original := make(map[string]bool, len(group.Members))
		for _, name := range group.Members {
			original[name] = true
		}
		group.Members = nil
		seen := make(map[string]bool, len(members))
		for _, id := range members {
			name := names[id]
			if name == "" || seen[name] || (groupNames[name] && !original[name]) {
				continue
			}
			seen[name] = true
			group.Members = append(group.Members, name)
		}
		if len(group.Members) == 0 {
			group.Members = []string{"REJECT"}
			warnings = append(warnings, fmt.Sprintf("策略组「%s」的自定义线路均不可用，暂时阻断", group.Name))
		}
		if !seen[group.Selected] {
			group.Selected = ""
		}
	}
	return warnings
}

func remapDetour(node *outbound.Node, names map[string]string) {
	if len(node.Options) == 0 {
		return
	}
	var options map[string]json.RawMessage
	var detour string
	if json.Unmarshal(node.Options, &options) != nil || json.Unmarshal(options["detour"], &detour) != nil {
		return // The engine reports malformed options during validation.
	}
	if mapped := names[detour]; mapped != "" && mapped != detour {
		options["detour"], _ = json.Marshal(mapped)
		node.Options, _ = json.Marshal(options)
	}
}

// prune drops references to outbounds that do not exist, which happens when
// the user's rules point at a subscription's groups before its first fetch.
func prune(config *engine.Config) []string {
	var warnings []string
	exists := map[string]bool{"DIRECT": true, "REJECT": true}
	for _, node := range config.Nodes {
		exists[node.Name] = true
	}
	for _, group := range config.Groups {
		exists[group.Name] = true
	}
	for i := range config.Groups {
		var members []string
		for _, member := range config.Groups[i].Members {
			if exists[member] {
				members = append(members, member)
			}
		}
		if len(members) == 0 {
			members = []string{"DIRECT"}
			warnings = append(warnings, fmt.Sprintf("策略组「%s」的成员都还不可用，暂时直连", config.Groups[i].Name))
		}
		if config.Groups[i].Selected != "" && !contains(members, config.Groups[i].Selected) {
			config.Groups[i].Selected = ""
		}
		config.Groups[i].Members = members
	}
	sets := map[string]bool{}
	for _, set := range config.RuleSets {
		sets[set.Name] = true
	}
	var rules []engine.Rule
	dropped := 0
	for _, rule := range config.Rules {
		if (rule.Via != "SELECT" && !exists[rule.Via]) || (rule.Type == engine.RuleRuleSet && !sets[rule.Value]) {
			dropped++
			continue
		}
		rules = append(rules, rule)
	}
	if dropped > 0 {
		warnings = append(warnings, fmt.Sprintf("%d 条规则指向的出站暂不存在，已暂时忽略", dropped))
	}
	config.Rules = rules
	if !exists[config.Selected] {
		warnings = append(warnings, fmt.Sprintf("选定出站「%s」暂不存在，暂时直连", config.Selected))
		config.Selected = "DIRECT"
	}
	return warnings
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// Loaded is the result of Load.
type Loaded struct {
	User     engine.Config // the user's file (or the last good copy of it)
	Merged   engine.Config // what the engine runs
	Warnings []string
	// SnapshotUpdated is keyed by subscription ID and uses Unix milliseconds.
	SnapshotUpdated map[string]int64
	Fallback        bool // the user's file was broken; the last good copy is in use
	Revision        string
	document        []byte
}

func lastGoodPath(dataDir string) string { return filepath.Join(dataDir, "last-good.json") }

// Load reads path, merges subscriptions and validates the result. If the
// file is unreadable or invalid and a last good copy exists, that copy is
// used instead and the problem is reported as a warning.
func Load(path, dataDir string, validate func(engine.Config) error) (Loaded, error) {
	return LoadContext(context.Background(), path, dataDir, validate)
}

func LoadContext(ctx context.Context, path, dataDir string, validate func(engine.Config) error) (Loaded, error) {
	if path != "" && dataDir != "" {
		release, err := LockWritesContext(ctx, dataDir)
		if err != nil {
			return Loaded{}, err
		}
		defer release()
	}
	loaded, err := load(path, dataDir, validate, previousDocument(path, dataDir))
	if cancelErr := ctx.Err(); cancelErr != nil {
		return Loaded{}, cancelErr
	}
	if err == nil {
		if err := SaveLastGood(path, dataDir, &loaded); err != nil {
			loaded.Warnings = append(loaded.Warnings, "无法保存回滚配置")
		} else if err := PruneSnapshots(path, dataDir); err != nil {
			loaded.Warnings = append(loaded.Warnings, "无法清理过期订阅缓存")
		}
		loaded.document = nil
		return loaded, nil
	}
	if dataDir == "" {
		return Loaded{}, err
	}
	fallback, fallbackErr := load(lastGoodPath(dataDir), dataDir, validate, nil)
	if fallbackErr != nil {
		return Loaded{}, err
	}
	fallback.Fallback = true
	fallback.document = nil
	fallback.Warnings = append([]string{"配置文件无效，正在使用上一次可用的配置：" + err.Error()}, fallback.Warnings...)
	return fallback, nil
}

// SaveLastGood records the validated configuration used by the caller.
func SaveLastGood(path, dataDir string, loaded *Loaded) error {
	data := loaded.document
	loaded.document = nil
	if path == "" || dataDir == "" {
		return nil
	}
	if data == nil {
		var err error
		if data, err = json.Marshal(loaded.User); err != nil {
			return err
		}
	}
	return engine.WriteAtomic(lastGoodPath(dataDir), data)
}

// Check validates path with its subscriptions, without any fallback.
func Check(path, dataDir string, validate func(engine.Config) error) (Loaded, error) {
	return load(path, dataDir, validate, previousDocument(path, dataDir))
}

func previousDocument(path, dataDir string) *Document {
	if path == "" || dataDir == "" {
		return nil
	}
	document, err := ReadDocument(lastGoodPath(dataDir))
	if err != nil || document.Bytes == nil {
		return nil
	}
	return &document
}

// CheckReplacement validates a newly edited on-disk profile against the
// current running configuration, while allowing a refresh of the same file.
func CheckReplacement(path, dataDir string, running Loaded, validate func(engine.Config) error) (Loaded, error) {
	candidate, err := load(path, dataDir, validate, &Document{Revision: running.Revision, config: &running.User})
	if err != nil {
		return Loaded{}, err
	}
	return candidate, validateReferenceBindings(running, candidate)
}

func load(path, dataDir string, validate func(engine.Config) error, previous *Document) (Loaded, error) {
	document, err := ReadDocument(path)
	if err != nil {
		return Loaded{}, err
	}
	if path == lastGoodPath(dataDir) && document.Bytes == nil {
		return Loaded{}, os.ErrNotExist
	}
	user, err := document.Config()
	if err != nil {
		return Loaded{}, err
	}
	var baseline *engine.Config
	if previous != nil && previous.Revision != document.Revision {
		if config, err := previous.Config(); err == nil {
			baseline = &config
		}
	}
	loaded, err := validateConfig(user, dataDir, validate, "", nil, baseline)
	loaded.Revision, loaded.document = document.Revision, document.Bytes
	return loaded, err
}

// validateConfig may use a staged snapshot that is still invisible to readers.
func validateConfig(user engine.Config, dataDir string, validate func(engine.Config) error, stagedName string, staged *Snapshot, previous *engine.Config) (Loaded, error) {
	user.DataDir = dataDir
	if n := user.SubscriptionRefreshMin; n != 0 && (n < 10 || n > 10080) {
		return Loaded{}, errors.New("subscriptionRefreshMin must be between 10 and 10080")
	}
	if err := validateSubscriptions(user.Subscriptions); err != nil {
		return Loaded{}, err
	}
	snapshots := map[string]*Snapshot{}
	updated := map[string]int64{}
	var warnings []string
	for _, sub := range user.Subscriptions {
		snapshot := staged
		var err error
		if staged == nil || sub.Name != stagedName {
			snapshot, err = LoadSnapshot(dataDir, sub)
		}
		if err != nil {
			if !sub.Paused {
				warnings = append(warnings, fmt.Sprintf("订阅「%s」还没有下载过", sub.Name))
			}
			continue
		}
		snapshots[sub.Name] = snapshot
		updated[sub.Key()] = snapshot.Updated
	}
	merged, mergeWarnings := Merge(user, snapshots)
	if previous != nil {
		if err := validateReferences(user, merged, *previous, dataDir, stagedName); err != nil {
			return Loaded{}, err
		}
	}
	merged.DataDir = dataDir
	if err := validate(merged); err != nil {
		return Loaded{}, err
	}
	return Loaded{User: user, Merged: merged, Warnings: append(warnings, mergeWarnings...), SnapshotUpdated: updated}, nil
}

func validateSubscriptions(subs []engine.Subscription) error {
	names := map[string]bool{}
	for _, sub := range subs {
		if sub.Name == "" || names[sub.Name] {
			return fmt.Errorf("invalid or duplicate subscription name %q", sub.Name)
		}
		names[sub.Name] = true
		if !strings.HasPrefix(sub.URL, "https://") && !strings.HasPrefix(sub.URL, "http://") {
			return fmt.Errorf("subscription %q url must be http or https", sub.Name)
		}
		if sub.Interval != 0 && sub.Interval < 600 {
			return fmt.Errorf("subscription %q interval must be at least 600 seconds", sub.Name)
		}
		if sub.SnapshotKey != "" && !validSnapshotKey(sub.SnapshotKey) {
			return fmt.Errorf("subscription %q snapshot key is invalid", sub.Name)
		}
	}
	return nil
}
