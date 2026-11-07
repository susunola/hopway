// Package app runs the engine for the lifetime of the process: it loads the
// profile, swaps engines on reload without dropping open connections, and
// refreshes subscriptions in the background.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/engine"
	"mac-proxy/internal/netmon"
	"mac-proxy/internal/profile"
	"mac-proxy/internal/sysproxy"
	"mac-proxy/internal/tun"
)

type SubscriptionStatus struct {
	Name    string                    `json:"name"`
	ID      string                    `json:"id"`
	Alias   string                    `json:"alias,omitempty"`
	Usage   *engine.SubscriptionUsage `json:"usage,omitempty"`
	Nodes   int                       `json:"nodes"`
	Updated int64                     `json:"updated,omitempty"`
	Checked int64                     `json:"checked,omitempty"`
	Error   string                    `json:"error,omitempty"`
}

type SystemProxyStatus struct {
	Supported bool   `json:"supported"`
	Enabled   bool   `json:"enabled"`
	Error     string `json:"error,omitempty"`
	Recovered bool   `json:"recovered,omitempty"` // settings left by a crashed run were restored at start
}

type TUNStatus struct {
	Supported bool             `json:"supported"`
	Enabled   bool             `json:"enabled"`
	Service   bool             `json:"service"` // the password-free service is installed and answering
	Device    string           `json:"device,omitempty"`
	Error     string           `json:"error,omitempty"`
	Operation string           `json:"operation,omitempty"`
	FakeIP    *tun.FakeIPStats `json:"fakeIP,omitempty"`
}

type Status struct {
	engine.Status
	SystemProxy   SystemProxyStatus    `json:"systemProxy"`
	TUN           TUNStatus            `json:"tun"`
	Network       []netmon.Event       `json:"network,omitempty"` // recent changes, newest last
	Warnings      []string             `json:"warnings,omitempty"`
	Subscriptions []SubscriptionStatus `json:"subscriptions,omitempty"`
	Reloaded      int64                `json:"reloaded,omitempty"` // unix ms of the running configuration
}

type Supervisor struct {
	path, dataDir string
	impl          backend.Backend
	ports         []int
	lease         *os.File

	ledger           *engine.TrafficLedger
	budget           *engine.ResourceBudget
	refreshMu        sync.Mutex
	current          atomic.Pointer[engine.Engine]
	mu               sync.Mutex // serializes reloads; guards the fields below
	loaded           profile.Loaded
	autoPolicy       *engine.Policy
	subErr           map[string]string
	subMeta          map[string]SubscriptionStatus // nodes and update time of each snapshot
	subReloadPending bool
	started          time.Time
	ctx              context.Context
	cancel           context.CancelFunc
	networkCtx       context.Context
	cancelNetwork    context.CancelFunc
	closing          bool
	closeOnce        sync.Once
	retiring         sync.WaitGroup

	proxyMu     sync.Mutex
	proxy       *sysproxy.Manager
	proxyTarget sysproxy.Target
	proxyErr    string
	recovered   bool
	events      []netmon.Event

	tunMu        sync.Mutex // serializes TUN changes; the helper prompt can take minutes
	tunDevice    *tun.Service
	tunName      string
	tunErr       string
	tunOperation string
	tunTask      sync.WaitGroup
}

var ErrTUNBusy = errors.New("正在处理另一项增强模式操作")

// TUNSupported is true where HopWay can create the device: macOS through
// the privileged helper, Linux when running as root.
var TUNSupported = runtime.GOOS == "darwin" || (runtime.GOOS == "linux" && os.Geteuid() == 0)

// Retirement: an engine replaced by a reload keeps serving its open
// connections and is closed once they finish, or after this long.
const retireAfter = 10 * time.Minute

var ErrProfileInUse = errors.New("HopWay 已在使用此配置")

// Open claims the profile and recovers any abandoned network settings.
// The caller must close it even if the listeners or Start fail afterward.
func Open(path, dataDir string, impl backend.Backend) (*Supervisor, error) {
	lease, err := acquireLease(dataDir)
	if err != nil {
		return nil, err
	}
	s := &Supervisor{path: path, dataDir: dataDir, impl: impl, lease: lease,
		budget: engine.NewResourceBudget(), subErr: map[string]string{}, subMeta: map[string]SubscriptionStatus{}}
	s.proxy = sysproxy.New(dataDir, nil)
	var recoveryErr error
	if SystemProxySupported {
		// Recover before loading the profile: even a broken profile must
		// not leave the previous process's dead proxy or DNS address in use.
		s.recovered, recoveryErr = s.proxy.Recover()
		if recoveryErr != nil {
			s.proxyErr = "无法还原上次的系统代理设置：" + recoveryErr.Error()
		}
	}
	loaded, err := profile.Load(path, dataDir, s.validate)
	if err != nil {
		if lease != nil {
			lease.Close()
		}
		return nil, errors.Join(err, recoveryErr)
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.networkCtx, s.cancelNetwork = context.WithCancel(s.ctx)
	s.loaded = loaded
	s.loadAutoPolicy()
	s.readSnapshotMeta()
	return s, nil
}

// SystemProxySupported is true where networksetup exists.
var SystemProxySupported = runtime.GOOS == "darwin"

// readSnapshotMeta caches snapshot sizes so Status never touches the disk.
func (s *Supervisor) readSnapshotMeta() {
	for _, sub := range s.loaded.User.Subscriptions {
		if snapshot, err := profile.LoadSnapshot(s.dataDir, sub); err == nil {
			s.subMeta[sub.URL] = SubscriptionStatus{Nodes: len(snapshot.Nodes), Updated: snapshot.Updated, Checked: snapshot.CheckedAt(), Usage: snapshot.Usage}
		}
	}
}

func (s *Supervisor) validate(config engine.Config) error { return engine.Validate(config, s.impl) }

func (s *Supervisor) Config() engine.Config { return s.loaded.Merged }

// Start builds the engine; ports are HopWay's own listeners. target is
// where the system proxy points when it is enabled.
func (s *Supervisor) Start(target sysproxy.Target, ports ...int) error {
	core, err := engine.NewWithResourceBudget(s.loaded.Merged, s.impl, s.budget, ports...)
	if err != nil {
		return err
	}
	if s.path != "" {
		ledger, err := engine.OpenTrafficLedger(filepath.Join(filepath.Dir(s.path), "traffic-history.json"))
		if err == nil {
			s.ledger = ledger
			core.SetTrafficLedger(ledger)
		} else {
			s.loaded.Warnings = append(s.loaded.Warnings, "无法记录本机用量："+err.Error())
		}
	}
	s.ports = ports
	s.proxyTarget = target
	s.started = time.Now()
	if s.autoPolicy != nil {
		core.Restore(engine.Runtime{Policy: *s.autoPolicy})
	}
	s.current.Store(core)
	if s.ledger != nil {
		go s.flushTraffic()
	}
	if s.loaded.Merged.SystemProxy {
		s.SetSystemProxy(true)
	}
	if t := s.loaded.Merged.TUN; t != nil && t.Enabled {
		_ = s.StartTUNChange(true) // may wait for the user to enter a password
	}
	go s.subscriptionLoop()
	go netmon.Watch(s.ctx, 3*time.Second, nil, s.networkChanged)
	return nil
}

// StartTUNChange records the operation before acknowledging the request.
func (s *Supervisor) StartTUNChange(enabled bool) error {
	operation := "disable"
	if enabled {
		operation = "enable"
	}
	return s.startTUNOperation(operation, func() error { return s.setTUN(enabled) })
}

// StartTUNServiceChange asynchronously installs or removes the TUN helper.
func (s *Supervisor) StartTUNServiceChange(installed bool) error {
	operation := "remove-helper"
	if installed {
		operation = "install-helper"
	}
	return s.startTUNOperation(operation, func() error { return s.setTUNService(installed) })
}

func (s *Supervisor) startTUNOperation(operation string, apply func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return net.ErrClosed
	}
	if s.tunOperation != "" {
		return ErrTUNBusy
	}
	s.tunOperation, s.tunErr = operation, ""
	s.tunTask.Add(1)
	go func() {
		defer s.tunTask.Done()
		err := apply()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.tunOperation = ""
		if err != nil && !s.closing {
			s.tunErr = err.Error()
		}
	}()
	return nil
}

// setTUN turns the TUN device on or off. On macOS without root this shows
// the system's administrator password dialog once per start.
func (s *Supervisor) setTUN(enabled bool) error {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	return s.setTUNLocked(enabled)
}

func (s *Supervisor) setTUNLocked(enabled bool) error {
	if !enabled {
		if s.tunDevice == nil {
			return nil
		}
		var restoreErr error
		if SystemProxySupported {
			restoreErr = s.proxy.RestoreDNS()
			if restoreErr != nil && !s.isClosing() {
				return restoreErr
			}
		}
		err := s.tunDevice.Close()
		s.mu.Lock()
		s.tunDevice, s.tunName = nil, ""
		s.mu.Unlock()
		return errors.Join(restoreErr, err)
	}
	if s.tunDevice != nil {
		return nil
	}
	if !TUNSupported {
		return errors.New("TUN mode needs macOS, or root on Linux")
	}
	s.mu.Lock()
	closing := s.closing
	t := s.loaded.Merged.TUN
	s.mu.Unlock()
	if closing {
		return net.ErrClosed
	}
	options := tun.Options{}
	if t != nil {
		options.MTU, options.IPv6 = t.MTU, t.IPv6
	}
	if err := options.CheckFakeIPNetworks(); err != nil {
		return err
	}
	// Read the real DNS servers before the system DNS is pointed at the device.
	options.LocalDNS = tun.SystemDNS(options.DNSAddress())
	options.UpstreamDNS = options.LocalDNS
	if len(options.UpstreamDNS) == 0 {
		options.UpstreamDNS = []string{"223.5.5.5:53", "1.1.1.1:53"}
	}
	if os.Geteuid() == 0 {
		options.AutoRoute = true
	} else if tun.ServiceAvailable(tun.ServiceSocket) {
		fd, name, err := tun.OpenWithService(s.ctx, tun.ServiceSocket, options)
		if err != nil {
			return fmt.Errorf("TUN service: %w", err)
		}
		options.FD, options.Name = fd, name
	} else {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		fd, name, err := tun.OpenWithHelper(s.ctx, executable, options)
		if err != nil {
			return err
		}
		options.FD, options.Name = fd, name
	}
	device, err := tun.Start(options, s.Dial, s.DialPacket)
	if err != nil {
		return err
	}
	name := options.Name
	if SystemProxySupported {
		// A DNS server on the local network has a more specific route than
		// the tunnel; point the system at the device so queries reach it.
		if err := s.proxy.SetDNS(options.DNSAddress().String()); err != nil {
			return errors.Join(fmt.Errorf("cannot point the system DNS at the tunnel: %w", err),
				s.proxy.RestoreDNS(), device.Close())
		}
	}
	s.mu.Lock()
	s.tunDevice, s.tunName = device, name
	s.mu.Unlock()
	return nil
}

// SetSystemProxy turns the macOS system proxy on or off.
func (s *Supervisor) SetSystemProxy(enabled bool) error {
	if !SystemProxySupported {
		return errors.New("system proxy settings are only supported on macOS")
	}
	s.proxyMu.Lock()
	defer s.proxyMu.Unlock()
	if s.isClosing() {
		return net.ErrClosed
	}
	var err error
	if enabled {
		err = s.proxy.Enable(s.proxyTarget)
	} else {
		err = s.proxy.Disable()
	}
	s.mu.Lock()
	s.proxyErr = ""
	if err != nil {
		s.proxyErr = err.Error()
	}
	s.mu.Unlock()
	return err
}

// serviceInstalled checks the files only; status polling must not wake the
// root service.
func serviceInstalled() bool {
	if _, err := os.Stat(tun.ServicePlist); err != nil {
		return false
	}
	_, err := os.Stat(tun.ServiceSocket)
	return err == nil
}

// setTUNService installs or removes the password-free TUN service. Either
// way macOS asks for the administrator password once.
func (s *Supervisor) setTUNService(installed bool) error {
	if runtime.GOOS != "darwin" {
		return errors.New("the TUN service is only used on macOS")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if installed {
		return tun.RunAsAdmin(s.ctx, executable, "安装 HopWay 增强模式服务后，开启增强模式（TUN）时不再需要输入密码。",
			"-tun-install", strconv.Itoa(os.Getuid()))
	}
	return tun.RunAsAdmin(s.ctx, executable, "卸载 HopWay 增强模式服务。", "-tun-uninstall")
}

func (s *Supervisor) networkChanged(event netmon.Event) {
	s.tunMu.Lock()
	if s.isClosing() {
		s.tunMu.Unlock()
		return
	}
	s.mu.Lock()
	s.cancelNetwork()
	s.networkCtx, s.cancelNetwork = context.WithCancel(s.ctx)
	current := s.current.Load()
	s.mu.Unlock()
	current.NetworkChanged()
	if s.tunDevice != nil {
		s.tunDevice.ResetNetwork()
	}
	s.tunMu.Unlock()
	s.proxyMu.Lock()
	if SystemProxySupported && !s.isClosing() {
		if _, err := s.proxy.Refresh(); err != nil {
			s.mu.Lock()
			s.proxyErr = err.Error()
			s.mu.Unlock()
		}
	}
	s.proxyMu.Unlock()
	s.mu.Lock()
	s.events = append(s.events, event)
	if len(s.events) > 10 {
		s.events = s.events[len(s.events)-10:]
	}
	s.mu.Unlock()
}

func (s *Supervisor) Engine() *engine.Engine { return s.current.Load() }

func (s *Supervisor) Dial(ctx context.Context, inbound, target string) (net.Conn, error) {
	return s.current.Load().Dial(ctx, inbound, target)
}

func (s *Supervisor) DialPacket(ctx context.Context, inbound, target string) (net.PacketConn, error) {
	return s.current.Load().DialPacket(ctx, inbound, target)
}

func (s *Supervisor) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

func (s *Supervisor) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.mu.Unlock()
		if s.cancel != nil {
			s.cancel()
		}
		s.proxyMu.Lock()
		if SystemProxySupported {
			if err := s.proxy.Disable(); err != nil {
				log.Printf("restore system proxy: %v", err)
			}
		}
		s.proxyMu.Unlock()
		s.tunTask.Wait()
		if err := s.setTUN(false); err != nil {
			log.Printf("close TUN: %v", err)
		}
		if core := s.current.Load(); core != nil {
			core.Close()
		}
		s.retiring.Wait()
		s.refreshMu.Lock()
		s.refreshMu.Unlock()
		if s.ledger != nil {
			_ = s.ledger.Close()
		}
		if s.lease != nil {
			_ = s.lease.Close()
		}
	})
}

var ErrPortsChanged = errors.New("监听端口已修改")

// Reload re-reads the profile and swaps in a new engine. New connections use
// it at once; open ones finish on the old engine.
func (s *Supervisor) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloadLocked()
}

func (s *Supervisor) reloadLocked() error {
	if s.closing {
		return net.ErrClosed
	}
	loaded, err := profile.Check(s.path, s.dataDir, s.validate)
	if err != nil {
		return err
	}
	old := s.current.Load()
	running := s.loaded.Merged
	if loaded.Merged.SOCKSPort != running.SOCKSPort || loaded.Merged.HTTPPort != running.HTTPPort {
		return ErrPortsChanged
	}
	core, err := engine.NewWithResourceBudget(loaded.Merged, s.impl, s.budget, s.ports...)
	if err != nil {
		return err
	}
	core.SetTrafficLedger(s.ledger)
	if old != nil {
		state := old.Runtime()
		if s.autoPolicy != nil {
			state.Policy = *s.autoPolicy
		}
		core.Restore(state)
	}
	s.loaded = loaded
	s.readSnapshotMeta()
	s.subReloadPending = false
	s.started = time.Now()
	s.current.Store(core)
	if err := profile.SaveLastGood(s.path, s.dataDir, loaded.User); err != nil {
		s.loaded.Warnings = append(s.loaded.Warnings, "无法保存回滚配置")
	}
	if old != nil {
		old.BeginDrain()
		s.retiring.Add(1)
		go func() {
			defer s.retiring.Done()
			retire(s.ctx, old)
		}()
	}
	return nil
}

func retire(ctx context.Context, old *engine.Engine) {
	defer old.Close()
	deadline := time.NewTimer(retireAfter)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for old.Active() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-ticker.C:
		}
	}
}

func (s *Supervisor) Status() Status {
	status := Status{Status: s.current.Load().Status()}
	s.mu.Lock()
	defer s.mu.Unlock()
	status.Warnings = s.loaded.Warnings
	status.SystemProxy = SystemProxyStatus{Supported: SystemProxySupported, Enabled: s.proxy.Enabled(),
		Error: s.proxyErr, Recovered: s.recovered}
	status.Network = append([]netmon.Event(nil), s.events...)
	status.TUN = TUNStatus{Supported: TUNSupported, Enabled: s.tunDevice != nil, Device: s.tunName, Error: s.tunErr,
		Service: runtime.GOOS == "darwin" && serviceInstalled(), Operation: s.tunOperation}
	if s.tunDevice != nil {
		fakeIP := s.tunDevice.FakeIPStats()
		status.TUN.FakeIP = &fakeIP
	}
	status.Reloaded = s.started.UnixMilli()
	for _, sub := range s.loaded.User.Subscriptions {
		entry := s.subMeta[sub.URL]
		entry.Name, entry.ID, entry.Alias, entry.Error = sub.Name, sub.Key(), sub.Alias, s.subErr[sub.Name]
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
	s.refreshSubscriptions(ctx, force, "")
}

func (s *Supervisor) RefreshSubscription(ctx context.Context, id string) {
	s.refreshSubscriptions(ctx, true, id)
}

func (s *Supervisor) refreshSubscriptions(ctx context.Context, force bool, id string) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	network := s.networkCtx
	user := s.loaded.User
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(network, cancel)
	defer stop()
	var transport *http.Transport
	var transportCore *engine.Engine
	defer func() {
		if transport != nil {
			transport.CloseIdleConnections()
		}
	}()
	for _, sub := range user.Subscriptions {
		if ctx.Err() != nil || network.Err() != nil {
			break
		}
		if sub.Paused || (id != "" && sub.Key() != id) {
			continue
		}
		s.mu.Lock()
		meta, known := s.subMeta[sub.URL]
		s.mu.Unlock()
		if known && !force && time.Since(time.UnixMilli(meta.Checked)) < profile.RefreshInterval(user, sub) {
			continue
		}
		if core := s.current.Load(); core != transportCore {
			if transport != nil {
				transport.CloseIdleConnections()
			}
			transport = &http.Transport{
				DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
					return core.Dial(ctx, "subscription", address)
				},
				ForceAttemptHTTP2: true, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 16,
			}
			transportCore = core
		}
		refresh, err := profile.FetchRefresh(ctx, sub, s.dataDir, s.impl, transport)
		s.mu.Lock()
		// Check the generation and the subscription again under the same
		// lock that serializes network events and profile changes.
		if ctx.Err() != nil || s.closing || network != s.networkCtx {
			s.mu.Unlock()
			break
		}
		current, exists := s.currentSubscription(sub)
		if !exists {
			s.mu.Unlock()
			continue
		}
		if err == nil {
			var changed bool
			changed, err = profile.CommitRefresh(s.loaded.User, current, refresh, s.dataDir, s.impl)
			s.subReloadPending = s.subReloadPending || changed
		}
		if err != nil {
			s.subErr[current.Name] = err.Error()
		} else {
			snapshot := refresh.Snapshot
			delete(s.subErr, current.Name)
			s.subMeta[current.URL] = SubscriptionStatus{Nodes: len(snapshot.Nodes), Updated: snapshot.Updated, Checked: snapshot.CheckedAt(), Usage: snapshot.Usage}
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subReloadPending && !s.closing {
		if err := s.reloadLocked(); err != nil {
			warning := "订阅已更新，但新配置无法应用：" + err.Error()
			if len(s.loaded.Warnings) == 0 || s.loaded.Warnings[len(s.loaded.Warnings)-1] != warning {
				s.loaded.Warnings = append(s.loaded.Warnings, warning)
			}
		}
	}
}

// currentSubscription is called with mu held. A rename does not invalidate
// the download, but replacing or pausing the source does.
func (s *Supervisor) currentSubscription(previous engine.Subscription) (engine.Subscription, bool) {
	for _, current := range s.loaded.User.Subscriptions {
		if !current.Paused && current.Key() == previous.Key() && current.URL == previous.URL && current.Agent == previous.Agent {
			return current, true
		}
	}
	return engine.Subscription{}, false
}

func (s *Supervisor) autoPolicyPath() string {
	return filepath.Join(s.dataDir, "auto-policy.json")
}

func (s *Supervisor) loadAutoPolicy() {
	if s.path == "" || s.dataDir == "" {
		return
	}
	data, err := os.ReadFile(s.autoPolicyPath())
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var policy engine.Policy
	if err != nil || json.Unmarshal(data, &policy) != nil || policy.Mode != "auto" || policy.Auto == nil {
		s.loaded.Warnings = append(s.loaded.Warnings, "无法恢复上次的自动选路设置")
		return
	}
	s.autoPolicy = &policy
}

func (s *Supervisor) SetPolicy(policy engine.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return net.ErrClosed
	}
	core := s.Engine()
	if err := core.ValidatePolicy(policy); err != nil {
		return err
	}
	if s.path != "" && s.dataDir != "" {
		if policy.Mode == "auto" {
			data, err := json.Marshal(policy)
			if err != nil {
				return err
			}
			if err := engine.WriteAtomic(s.autoPolicyPath(), data); err != nil {
				return errors.New("无法保存自动选路设置")
			}
		} else if err := os.Remove(s.autoPolicyPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("无法清除上次的自动选路设置")
		}
	}
	if policy.Mode == "auto" {
		s.autoPolicy = &policy
	} else {
		s.autoPolicy = nil
	}
	return core.SetPolicy(policy)
}

func (s *Supervisor) flushTraffic() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			_ = s.ledger.Flush()
		}
	}
}
