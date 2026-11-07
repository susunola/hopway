package profile

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/importer"
)

// Fetch downloads a subscription and converts it to a snapshot.
func Fetch(ctx context.Context, sub engine.Subscription, impl backend.Backend, transport http.RoundTripper) (*Snapshot, importer.Result, error) {
	result, err := importer.ImportWith(ctx, strings.NewReader(sub.URL), engine.Default(), impl, importer.Options{Transport: transport})
	if err != nil {
		return nil, importer.Result{}, err
	}
	config := result.Config
	snapshot := &Snapshot{URL: sub.URL, Updated: time.Now().UnixMilli(), Nodes: config.Nodes, Groups: config.Groups,
		RuleSets: config.RuleSets, Health: config.Health, Skipped: result.Skipped, Notes: result.Notes}
	if len(config.Groups) != 0 {
		snapshot.Rules = config.Rules // Clash profiles bring their own routing
	}
	return snapshot, result, nil
}

// Subscribe adds (or refreshes) a subscription in user, downloading it now.
// The returned result's Config is the user configuration to save; the nodes
// live in the snapshot, not in the file, so later refreshes never rewrite it.
func Subscribe(ctx context.Context, user engine.Config, rawURL, dataDir string, impl backend.Backend) (importer.Result, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return importer.Result{}, fmt.Errorf("订阅地址无效")
	}
	sub := engine.Subscription{Name: parsed.Hostname(), URL: rawURL}
	index := -1
	names := map[string]bool{}
	for i, existing := range user.Subscriptions {
		if existing.URL == rawURL {
			index, sub = i, existing
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
	}
	merged, _ := Merge(user, map[string]*Snapshot{sub.Name: snapshot})
	merged.DataDir = dataDir
	if err := engine.Validate(merged, impl); err != nil {
		return importer.Result{}, err
	}
	if err := SaveSnapshot(dataDir, sub, snapshot); err != nil {
		return importer.Result{}, err
	}
	user.DataDir = ""
	result.Config = user
	verb := "已添加订阅"
	if index >= 0 {
		verb = "已更新订阅"
	}
	for i, note := range result.Notes {
		result.Notes[i] = strings.Replace(note, "替换原有分组和规则", "排在你自己的规则之后生效", 1)
	}
	result.Notes = append([]string{fmt.Sprintf("%s「%s」，之后每 %d 小时自动更新", verb, sub.Name, interval(sub)/3600)}, result.Notes...)
	return result, nil
}

const DefaultInterval = 12 * 3600

func interval(sub engine.Subscription) int {
	if sub.Interval > 0 {
		return sub.Interval
	}
	return DefaultInterval
}
