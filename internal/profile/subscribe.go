package profile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/importer"
	"mac-proxy/internal/outbound"
)

// Fetch downloads a subscription without using an earlier response.
func Fetch(ctx context.Context, sub engine.Subscription, impl backend.Backend, transport http.RoundTripper) (*Snapshot, importer.Result, error) {
	return fetch(ctx, sub, impl, transport, nil)
}

func fetch(ctx context.Context, sub engine.Subscription, impl backend.Backend, transport http.RoundTripper, previous *Snapshot) (*Snapshot, importer.Result, error) {
	options := importer.Options{Transport: transport, Agent: sub.Agent}
	if previous != nil && previous.Validators != nil {
		options.Validators = *previous.Validators
	}
	result, err := importer.ImportWith(ctx, strings.NewReader(sub.URL), engine.Default(), impl, options)
	if err != nil {
		return nil, importer.Result{}, err
	}
	now := time.Now().UnixMilli()
	if result.NotModified {
		snapshot := *previous
		snapshot.Checked, snapshot.Validators = now, &result.Validators
		return &snapshot, result, nil
	}
	config := result.Config
	if len(config.Nodes) == 0 {
		return nil, importer.Result{}, errors.New("订阅没有可用节点")
	}
	snapshot := &Snapshot{Updated: now, Checked: now, Validators: &result.Validators,
		Nodes: config.Nodes, Groups: config.Groups, RuleSets: config.RuleSets,
		Health: config.Health, Usage: result.Usage, Skipped: result.Skipped, Notes: result.Notes}
	if len(config.Groups) != 0 {
		snapshot.Rules = config.Rules // Clash profiles bring their own routing
	}
	return snapshot, result, nil
}

type Refresh struct {
	Snapshot    *Snapshot
	previous    *Snapshot
	notModified bool
}

// FetchRefresh keeps the snapshot a conditional response refers to, so a
// concurrent import cannot have its nodes overwritten by a stale HTTP 304.
func FetchRefresh(ctx context.Context, sub engine.Subscription, dataDir string, impl backend.Backend, transport http.RoundTripper) (*Refresh, error) {
	if err := checkRetry(sub, dataDir); err != nil {
		return nil, err
	}
	previous, _ := LoadSnapshot(dataDir, sub)
	snapshot, result, err := fetch(ctx, sub, impl, transport, previous)
	if err != nil {
		saveRetry(sub, dataDir, err)
		return nil, err
	}
	return &Refresh{Snapshot: snapshot, previous: previous, notModified: result.NotModified}, nil
}

// RefreshSnapshot downloads and validates before replacing a cached snapshot.
func RefreshSnapshot(ctx context.Context, user engine.Config, sub engine.Subscription, dataDir string, impl backend.Backend, transport http.RoundTripper) (*Snapshot, error) {
	refresh, err := FetchRefresh(ctx, sub, dataDir, impl, transport)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := CommitRefresh(user, sub, refresh, dataDir, impl); err != nil {
		return nil, err
	}
	return refresh.Snapshot, nil
}

// CommitRefresh reports whether the engine-facing content actually changed.
func CommitRefresh(user engine.Config, sub engine.Subscription, refresh *Refresh, dataDir string, impl backend.Backend) (bool, error) {
	release, err := lockSnapshots(dataDir)
	if err != nil {
		return false, err
	}
	defer release()
	current, _ := LoadSnapshot(dataDir, sub)
	if !reflect.DeepEqual(current, refresh.previous) {
		return false, errors.New("订阅缓存已由其他操作更新，请重新检查")
	}
	snapshot := refresh.Snapshot
	changed := !sameRouting(current, snapshot)
	if changed {
		if err := prepareSnapshot(user, sub, snapshot, dataDir, impl); err != nil {
			return false, err
		}
	} else {
		snapshot.Updated = current.Updated
		if !refresh.notModified {
			updateUsage(sub, snapshot, current)
		}
	}
	if err := saveSnapshot(dataDir, sub, snapshot); err != nil {
		return false, err
	}
	return changed, nil
}

func sameRouting(a, b *Snapshot) bool {
	return a != nil && slices.EqualFunc(a.Nodes, b.Nodes, sameNode) &&
		equalSlice(a.Groups, b.Groups) && equalSlice(a.Rules, b.Rules) &&
		equalSlice(a.RuleSets, b.RuleSets) && reflect.DeepEqual(a.Health, b.Health)
}

func equalSlice[T any](a, b []T) bool {
	return slices.EqualFunc(a, b, func(a, b T) bool { return reflect.DeepEqual(a, b) })
}

func sameNode(a, b outbound.Node) bool {
	aOptions, bOptions := a.Options, b.Options
	a.Options, b.Options = nil, nil
	if !reflect.DeepEqual(a, b) {
		return false
	}
	if bytes.Equal(aOptions, bOptions) {
		return true
	}
	var left, right bytes.Buffer
	return json.Compact(&left, aOptions) == nil && json.Compact(&right, bOptions) == nil &&
		bytes.Equal(left.Bytes(), right.Bytes())
}

func updateUsage(sub engine.Subscription, snapshot, previous *Snapshot) {
	if previous != nil {
		sub.Usage, sub.UsageSamples = previous.Usage, previous.Samples
	}
	if snapshot.Usage != nil {
		importer.UpdateUsage(&sub, snapshot.Usage)
	} else {
		snapshot.Usage = sub.Usage
	}
	snapshot.Samples = sub.UsageSamples
}

func prepareSnapshot(user engine.Config, sub engine.Subscription, snapshot *Snapshot, dataDir string, impl backend.Backend) error {
	snapshots := map[string]*Snapshot{sub.Name: snapshot}
	var previous *Snapshot
	for _, other := range user.Subscriptions {
		cached, err := LoadSnapshot(dataDir, other)
		if err != nil {
			continue
		}
		if other.Name == sub.Name {
			previous = cached
		} else {
			snapshots[other.Name] = cached
		}
	}
	updateUsage(sub, snapshot, previous)
	merged, _ := Merge(user, snapshots)
	merged.DataDir = dataDir
	return engine.Validate(merged, impl)
}

func checkRetry(sub engine.Subscription, dataDir string) error {
	until := time.Unix(readRetryDeadline(SnapshotPath(dataDir, sub)+".retry"), 0)
	if until.After(time.Now()) {
		return fmt.Errorf("订阅暂缓刷新，可在 %s 后重试", until.Local().Format("01-02 15:04:05"))
	}
	return nil
}

func readRetryDeadline(path string) int64 {
	raw, _ := os.ReadFile(path)
	seconds, _ := strconv.ParseInt(string(raw), 10, 64)
	return seconds
}

func saveRetry(sub engine.Subscription, dataDir string, err error) {
	var response *importer.DownloadError
	if !errors.As(err, &response) || !response.RetryAfter.After(time.Now()) {
		return
	}
	release, err := lockSnapshots(dataDir)
	if err != nil {
		return
	}
	defer release()
	// Round up so the next process cannot retry just before the hint.
	until := response.RetryAfter.Add(time.Second - time.Nanosecond).Unix()
	path := SnapshotPath(dataDir, sub) + ".retry"
	if until > readRetryDeadline(path) {
		_ = engine.WriteAtomic(path, strconv.AppendInt(nil, until, 10))
	}
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
	if err := checkRetry(sub, dataDir); err != nil {
		return importer.Result{}, err
	}
	snapshot, result, err := Fetch(ctx, sub, impl, nil)
	if err != nil {
		saveRetry(sub, dataDir, err)
		return importer.Result{}, err
	}
	if index < 0 {
		user.Subscriptions = append(user.Subscriptions, sub)
	} else {
		user.Subscriptions = append([]engine.Subscription(nil), user.Subscriptions...)
		user.Subscriptions[index] = sub
	}
	if !preview {
		release, err := lockSnapshots(dataDir)
		if err != nil {
			return importer.Result{}, err
		}
		defer release()
	}
	if err := prepareSnapshot(user, sub, snapshot, dataDir, impl); err != nil {
		return importer.Result{}, err
	}
	if !preview {
		if err := saveSnapshot(dataDir, sub, snapshot); err != nil {
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
	result.Notes = append([]string{fmt.Sprintf("%s「%s」，之后每 %g 分钟自动检查", verb, sub.Name, RefreshInterval(user, sub).Minutes())}, result.Notes...)
	return result, nil
}

func RefreshInterval(config engine.Config, sub engine.Subscription) time.Duration {
	if sub.Interval > 0 {
		return time.Duration(sub.Interval) * time.Second
	}
	if config.SubscriptionRefreshMin > 0 {
		return time.Duration(config.SubscriptionRefreshMin) * time.Minute
	}
	return 6 * time.Hour
}
