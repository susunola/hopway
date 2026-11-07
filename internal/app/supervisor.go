// Package app runs the engine for the lifetime of the process: it loads the
// profile, swaps engines on reload without dropping open connections, and
// refreshes subscriptions in the background.
package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/profile"
)

type SubscriptionStatus struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Nodes   int    `json:"nodes"`
	Updated int64  `json:"updated,omitempty"`
	Error   string `json:"error,omitempty"`
}

type Status struct {
	engine.Status
	Warnings      []string             `json:"warnings,omitempty"`
	Subscriptions []SubscriptionStatus `json:"subscriptions,omitempty"`
	Reloaded      int64                `json:"reloaded,omitempty"` // unix ms of the running configuration
}

type Supervisor struct {
	path, dataDir string
	impl          backend.Backend
	ports         []int

	current atomic.Pointer[engine.Engine]
	mu      sync.Mutex // serializes reloads; guards the fields below
	loaded  profile.Loaded
	subErr  map[string]string
	subMeta map[string]SubscriptionStatus // nodes and update time of each snapshot
	started time.Time
	ctx     context.Context
	cancel  context.CancelFunc
}

// Retirement: an engine replaced by a reload keeps serving its open
// connections and is closed once they finish, or after this long.
const retireAfter = 10 * time.Minute

// Open loads the profile. Listeners are opened by the caller, using
// Config().SOCKSPort and HTTPPort, before Start.
func Open(path, dataDir string, impl backend.Backend) (*Supervisor, error) {
	s := &Supervisor{path: path, dataDir: dataDir, impl: impl, subErr: map[string]string{}, subMeta: map[string]SubscriptionStatus{}}
	loaded, err := profile.Load(path, dataDir, s.validate)
	if err != nil {
		return nil, err
	}
	s.loaded = loaded
	s.readSnapshotMeta()
	return s, nil
}

// readSnapshotMeta caches snapshot sizes so Status never touches the disk.
func (s *Supervisor) readSnapshotMeta() {
	for _, sub := range s.loaded.User.Subscriptions {
		if snapshot, err := profile.LoadSnapshot(s.dataDir, sub); err == nil {
			s.subMeta[sub.URL] = SubscriptionStatus{Nodes: len(snapshot.Nodes), Updated: snapshot.Updated}
		}
	}
}

func (s *Supervisor) validate(config engine.Config) error { return engine.Validate(config, s.impl) }

func (s *Supervisor) Config() engine.Config { return s.loaded.Merged }

// Start builds the engine; ports are HopWay's own listeners.
func (s *Supervisor) Start(ports ...int) error {
	core, err := engine.New(s.loaded.Merged, s.impl, ports...)
	if err != nil {
		return err
	}
	s.ports = ports
	s.started = time.Now()
	s.current.Store(core)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	go s.subscriptionLoop()
	return nil
}

func (s *Supervisor) Engine() *engine.Engine { return s.current.Load() }

func (s *Supervisor) Dial(ctx context.Context, inbound, target string) (net.Conn, error) {
	return s.current.Load().Dial(ctx, inbound, target)
}

func (s *Supervisor) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if core := s.current.Load(); core != nil {
		core.Close()
	}
}

var ErrPortsChanged = errors.New("listening ports changed; restart HopWay to apply")

// Reload re-reads the profile and swaps in a new engine. New connections use
// it at once; open ones finish on the old engine.
func (s *Supervisor) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloadLocked()
}

func (s *Supervisor) reloadLocked() error {
	loaded, err := profile.Load(s.path, s.dataDir, s.validate)
	if err != nil {
		return err
	}
	old := s.current.Load()
	running := s.loaded.Merged
	if (loaded.Merged.SOCKSPort != running.SOCKSPort && loaded.Merged.SOCKSPort != 0) ||
		(loaded.Merged.HTTPPort != running.HTTPPort && loaded.Merged.HTTPPort != 0) {
		return ErrPortsChanged
	}
	core, err := engine.New(loaded.Merged, s.impl, s.ports...)
	if err != nil {
		return err
	}
	if old != nil {
		core.Restore(old.Runtime())
	}
	s.loaded = loaded
	s.readSnapshotMeta()
	s.started = time.Now()
	s.current.Store(core)
	if old != nil {
		go retire(old)
	}
	return nil
}

func retire(old *engine.Engine) {
	deadline := time.Now().Add(retireAfter)
	for old.Active() > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Second)
	}
	old.Close()
}

func (s *Supervisor) Status() Status {
	status := Status{Status: s.current.Load().Status()}
	s.mu.Lock()
	defer s.mu.Unlock()
	status.Warnings = s.loaded.Warnings
	status.Reloaded = s.started.UnixMilli()
	for _, sub := range s.loaded.User.Subscriptions {
		entry := s.subMeta[sub.URL]
		entry.Name, entry.URL, entry.Error = sub.Name, sub.URL, s.subErr[sub.Name]
		status.Subscriptions = append(status.Subscriptions, entry)
	}
	return status
}

const subscriptionCheck = 10 * time.Minute

func (s *Supervisor) subscriptionLoop() {
	for {
		s.RefreshSubscriptions(s.ctx, false)
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(subscriptionCheck):
		}
	}
}

// RefreshSubscriptions downloads stale subscriptions (all, if force) and
// reloads once if any changed. Downloads go through HopWay's own routing, so
// they work where the subscription host is only reachable via a node. A
// failed download keeps the previous snapshot.
func (s *Supervisor) RefreshSubscriptions(ctx context.Context, force bool) {
	s.mu.Lock()
	subs := append([]engine.Subscription(nil), s.loaded.User.Subscriptions...)
	s.mu.Unlock()
	changed := false
	for _, sub := range subs {
		interval := time.Duration(sub.Interval) * time.Second
		if sub.Interval == 0 {
			interval = profile.DefaultInterval * time.Second
		}
		s.mu.Lock()
		meta, known := s.subMeta[sub.URL]
		s.mu.Unlock()
		if known && !force && time.Since(time.UnixMilli(meta.Updated)) < interval {
			continue
		}
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				return s.Dial(ctx, "subscription", address)
			},
			ForceAttemptHTTP2: true,
		}
		snapshot, _, err := profile.Fetch(ctx, sub, s.impl, transport)
		transport.CloseIdleConnections()
		if err == nil {
			err = profile.SaveSnapshot(s.dataDir, sub, snapshot)
		}
		s.mu.Lock()
		if err != nil {
			s.subErr[sub.Name] = err.Error()
		} else {
			delete(s.subErr, sub.Name)
			s.subMeta[sub.URL] = SubscriptionStatus{Nodes: len(snapshot.Nodes), Updated: snapshot.Updated}
			changed = true
		}
		s.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
	}
	if changed {
		if err := s.Reload(); err != nil {
			s.mu.Lock()
			s.loaded.Warnings = append(s.loaded.Warnings, "订阅已更新，但新配置无法应用："+err.Error())
			s.mu.Unlock()
		}
	}
}
