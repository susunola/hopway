package profile

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/importer"
)

// Fetch downloads a subscription and converts it to a snapshot.
func Fetch(ctx context.Context, sub engine.Subscription, impl backend.Backend, transport http.RoundTripper) (*Snapshot, importer.Result, error) {
	result, err := importer.ImportWith(ctx, strings.NewReader(sub.URL), engine.Default(), impl, importer.Options{Transport: transport, Agent: sub.Agent})
	if err != nil {
		return nil, importer.Result{}, err
	}
	config := result.Config
	snapshot := &Snapshot{Updated: time.Now().UnixMilli(), Nodes: config.Nodes, Groups: config.Groups,
		RuleSets: config.RuleSets, Health: config.Health, Usage: result.Usage, Skipped: result.Skipped, Notes: result.Notes}
	if len(config.Groups) != 0 {
		snapshot.Rules = config.Rules // Clash profiles bring their own routing
	}
	return snapshot, result, nil
}

// RefreshSnapshot validates a new snapshot alongside all other subscriptions
// before replacing the cached version.
func RefreshSnapshot(ctx context.Context, user engine.Config, sub engine.Subscription, dataDir string, impl backend.Backend, transport http.RoundTripper) (*Snapshot, error) {
	snapshot, _, err := Fetch(ctx, sub, impl, transport)
	if err != nil {
		return nil, err
	}
	if err := prepareSnapshot(user, sub, snapshot, dataDir, impl); err != nil {
		return nil, err
	}
	return snapshot, SaveSnapshot(dataDir, sub, snapshot)
}

func prepareSnapshot(user engine.Config, sub engine.Subscription, snapshot *Snapshot, dataDir string, impl backend.Backend) error {
	snapshots := map[string]*Snapshot{sub.Name: snapshot}
	for _, other := range user.Subscriptions {
		cached, err := LoadSnapshot(dataDir, other)
		if err != nil {
			continue
		}
		if other.Name != sub.Name {
			snapshots[other.Name] = cached
			continue
		}
		sub.Usage, sub.UsageSamples = cached.Usage, cached.Samples
	}
	if snapshot.Usage != nil {
		importer.UpdateUsage(&sub, snapshot.Usage)
	} else {
		snapshot.Usage = sub.Usage
	}
	snapshot.Samples = sub.UsageSamples
	merged, _ := Merge(user, snapshots)
	merged.DataDir = dataDir
	return engine.Validate(merged, impl)
}

// Subscribe adds (or refreshes) a subscription in user, downloading it now.
// The returned result's Config is the user configuration to save; the nodes
// live in the snapshot, not in the file, so later refreshes never rewrite it.
func Subscribe(ctx context.Context, user engine.Config, rawURL, dataDir string, impl backend.Backend) (importer.Result, error) {
	return subscribe(ctx, user, rawURL, dataDir, impl, false)
}

func PreviewSubscription(ctx context.Context, user engine.Config, rawURL, dataDir string, impl backend.Backend) (importer.Result, error) {
	return subscribe(ctx, user, rawURL, dataDir, impl, true)
}

func subscribe(ctx context.Context, user engine.Config, rawURL, dataDir string, impl backend.Backend, preview bool) (importer.Result, error) {
	parsed, agent, label, err := importer.SubscriptionLink(rawURL)
	if err != nil || parsed == nil {
		return importer.Result{}, fmt.Errorf("订阅地址无效")
	}
	rawURL = parsed.String()
	sub := engine.Subscription{Name: parsed.Hostname(), URL: rawURL, Agent: agent,
		ID: fmt.Sprintf("%x", sha256.Sum256([]byte(rawURL)))}
	if label = strings.TrimSpace(label); label != "" {
		sub.Alias = label
	}
	index := -1
	names := map[string]bool{}
	for i, existing := range user.Subscriptions {
		if existing.URL == rawURL {
			index, sub = i, existing
			if sub.ID == "" {
				sub.ID = sub.Key()
			}
			if sub.Agent == "" || sub.Agent == "clash/HopWay" {
				sub.Agent = agent
			}
		}
		names[existing.Name] = true
	}
	if index < 0 {
		base := sub.Name
		for i := 2; names[sub.Name]; i++ {
			sub.Name = fmt.Sprintf("%s-%d", base, i)
		}
	}
	snapshot, result, err := Fetch(ctx, sub, impl, nil)
	if err != nil {
		return importer.Result{}, err
	}
	if index < 0 {
		user.Subscriptions = append(user.Subscriptions, sub)
	} else {
		user.Subscriptions = append([]engine.Subscription(nil), user.Subscriptions...)
		user.Subscriptions[index] = sub
	}
	if err := prepareSnapshot(user, sub, snapshot, dataDir, impl); err != nil {
		return importer.Result{}, err
	}
	if !preview {
		if err := SaveSnapshot(dataDir, sub, snapshot); err != nil {
			return importer.Result{}, err
		}
	}
	user.DataDir = ""
	result.Config = user
	verb := "已添加订阅"
	if index >= 0 {
		verb = "已更新订阅"
	}
	if preview {
		verb = "将添加订阅"
		if index >= 0 {
			verb = "将更新订阅"
		}
	}
	for i, note := range result.Notes {
		result.Notes[i] = strings.Replace(note, "替换原有分组和规则", "排在你自己的规则之后生效", 1)
	}
	result.Notes = append([]string{fmt.Sprintf("%s「%s」，之后每 %d 小时自动更新", verb, sub.Name, interval(sub)/3600)}, result.Notes...)
	return result, nil
}

const DefaultInterval = 6 * 3600

func interval(sub engine.Subscription) int {
	if sub.Interval > 0 {
		return sub.Interval
	}
	return DefaultInterval
}
