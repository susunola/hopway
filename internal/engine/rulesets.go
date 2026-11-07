package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mac-proxy/internal/ruleset"
)

// RuleSet is a named list referenced by "rule-set" rules. Remote sets are
// cached in the data directory, so HopWay starts with the last copy even
// offline, and refreshed in the background through HopWay's own routing.
type RuleSet struct {
	Name     string `json:"name"`
	URL      string `json:"url,omitempty"`
	Path     string `json:"path,omitempty"`
	Format   string `json:"format,omitempty"`   // srs, yaml, text (default: from the file name)
	Behavior string `json:"behavior,omitempty"` // domain, ipcidr, classical (yaml/text only)
	Interval int    `json:"intervalSec,omitempty"`
}

type RuleSetStatus struct {
	Name    string `json:"name"`
	Entries int    `json:"entries"`
	Skipped int    `json:"skipped,omitempty"`
	Updated int64  `json:"updated,omitempty"` // unix ms of the copy in use
	Error   string `json:"error,omitempty"`
}

const (
	RuleRuleSet             = "rule-set"
	defaultRuleSetInterval  = 86400
	maxRuleSetSize          = 32 << 20
	maxProfileRuleSetCost   = 256 << 20
	ruleSetCheck            = 10 * time.Minute
	ruleSetDownloadDeadline = 60 * time.Second
)

type ruleSetState struct {
	RuleSet
	slot    int
	format  string
	digest  [sha256.Size]byte
	content *ruleset.Content
	updated time.Time
	err     string
}

var errRuleSetProfileBudget = errors.New("rule sets exceed the profile's combined compilation budget")

type ruleSetKey struct {
	digest           [sha256.Size]byte
	format, behavior string
}

// RuleSetIndexes holds immutable indexes during one serial profile build.
// It is discarded after validation and the replacement engine have used it.
type RuleSetIndexes map[ruleSetKey]*ruleset.Content

func (engine *Engine) RuleSetIndexes() RuleSetIndexes {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	indexes := make(RuleSetIndexes, len(engine.ruleSets))
	for _, state := range engine.ruleSets {
		if state.content != nil {
			indexes[state.key(state.digest)] = state.content
		}
	}
	return indexes
}

func (state *ruleSetState) key(digest [sha256.Size]byte) ruleSetKey {
	return ruleSetKey{digest: digest, format: state.format, behavior: state.Behavior}
}

func (engine *Engine) openRuleSets(ctx context.Context, config Config, indexes RuleSetIndexes) error {
	interval := defaultRuleSetInterval
	if minutes := config.RuleSetRefreshMin; minutes != 0 {
		if minutes < 10 || minutes > 10080 {
			return errors.New("ruleSetRefreshMin must be between 10 and 10080")
		}
		interval = minutes * 60
	}
	names := make(map[string]bool, len(config.RuleSets))
	for _, rs := range config.RuleSets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if rs.Name == "" || names[rs.Name] {
			return fmt.Errorf("invalid or duplicate rule-set name %q", rs.Name)
		}
		if (rs.URL == "") == (rs.Path == "") {
			return fmt.Errorf("rule-set %q needs exactly one of url or path", rs.Name)
		}
		if rs.URL != "" && !strings.HasPrefix(rs.URL, "https://") && !strings.HasPrefix(rs.URL, "http://") {
			return fmt.Errorf("rule-set %q url must be http or https", rs.Name)
		}
		if rs.Interval != 0 && rs.Interval < 600 {
			return fmt.Errorf("rule-set %q interval must be at least 600 seconds", rs.Name)
		}
		state := &ruleSetState{RuleSet: rs, slot: len(engine.ruleSets), format: rs.Format}
		if state.format == "" {
			state.format = ruleset.DetectFormat(rs.URL + rs.Path)
		}
		if state.Interval == 0 {
			state.Interval = interval
		}
		switch state.format {
		case ruleset.FormatSRS, ruleset.FormatYAML, ruleset.FormatText:
		default:
			return fmt.Errorf("rule-set %q has unknown format %q", rs.Name, rs.Format)
		}
		path := rs.Path
		if path == "" {
			path = engine.cachePath(state)
		}
		if path != "" {
			data, updated, err := readRuleSetFile(ctx, path)
			if err == nil {
				key := state.key(sha256.Sum256(data))
				content := indexes[key]
				if content == nil {
					content, err = ruleset.ParseContext(ctx, state.format, state.Behavior, data)
				}
				if err == nil {
					if engine.ruleSetCost+content.MemoryCost() > maxProfileRuleSetCost {
						return fmt.Errorf("rule-set %q: %w", rs.Name, errRuleSetProfileBudget)
					}
					state.digest, state.content, state.updated = key.digest, content, updated
					engine.ruleSetCost += content.MemoryCost()
					if indexes != nil {
						indexes[key] = content
					}
				} else if rs.URL != "" {
					state.err = err.Error()
				}
			}
			if err != nil && rs.Path != "" {
				return fmt.Errorf("rule-set %q: %w", rs.Name, err)
			}
		}
		names[rs.Name] = true
		engine.ruleSets = append(engine.ruleSets, state)
	}
	return ctx.Err()
}

type ruleSetReader struct {
	ctx context.Context
	io.Reader
}

func (r ruleSetReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(data[:min(len(data), 64<<10)])
}

func readRuleSet(ctx context.Context, reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(ruleSetReader{ctx, reader}, maxRuleSetSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRuleSetSize {
		return nil, errors.New("rule set is larger than 32 MB")
	}
	return data, ctx.Err()
}

func readRuleSetFile(ctx context.Context, path string) ([]byte, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	// Opening a named pipe must never wait for a writer.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	if !info.Mode().IsRegular() {
		return nil, time.Time{}, errors.New("rule set must be a regular file")
	}
	if info.Size() > maxRuleSetSize {
		return nil, time.Time{}, errors.New("rule set is larger than 32 MB")
	}
	data := make([]byte, int(info.Size()))
	reader := ruleSetReader{ctx, file}
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, time.Time{}, err
	}
	var extra [1]byte
	if n, err := reader.Read(extra[:]); n != 0 {
		return nil, time.Time{}, errors.New("rule-set file changed while it was being read")
	} else if err != io.EOF {
		return nil, time.Time{}, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, time.Time{}, errors.New("rule-set file changed while it was being read")
	}
	return data, info.ModTime(), ctx.Err()
}

func (engine *Engine) cachePath(state *ruleSetState) string {
	if engine.dataDir == "" || state.URL == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(state.URL + "\x00" + state.format + "\x00" + state.Behavior))
	return filepath.Join(engine.dataDir, "rulesets", hex.EncodeToString(sum[:8])+"."+state.format)
}

func (engine *Engine) ruleSetLoop(ctx context.Context) {
	timer := time.NewTimer(ruleSetCheck)
	defer timer.Stop()
	for {
		engine.RefreshRuleSets(ctx, false)
		timer.Reset(ruleSetCheck)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

type RefreshResult struct {
	Succeeded int  `json:"succeeded"`
	Failed    int  `json:"failed"`
	Canceled  bool `json:"canceled"`
}

// RefreshRuleSets downloads stale remote sets. A forced refresh also reloads
// local files and rechecks every remote set.
func (engine *Engine) RefreshRuleSets(ctx context.Context, force bool) (result RefreshResult) {
	if engine.work == nil {
		return RefreshResult{Canceled: true}
	}
	ctx, done, ok := engine.work.Enter(ctx)
	if !ok {
		return RefreshResult{Canceled: true}
	}
	defer done()
	select {
	case <-ctx.Done():
		return RefreshResult{Canceled: true}
	case engine.ruleRefresh <- struct{}{}:
	}
	defer func() { <-engine.ruleRefresh }()
	engine.mu.Lock()
	network, epoch := engine.networkCtx, engine.networkEpoch.Load()
	engine.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(network, cancel)
	defer stop()
	defer func() { result.Canceled = ctx.Err() != nil || network.Err() != nil }()
	for _, state := range engine.ruleSets {
		if ctx.Err() != nil || network.Err() != nil {
			return
		}
		engine.mu.Lock()
		stale := force || state.URL != "" && (state.content == nil ||
			time.Since(state.updated) > time.Duration(state.Interval)*time.Second)
		engine.mu.Unlock()
		if !stale {
			continue
		}
		err := engine.refreshRuleSet(ctx, state, epoch)
		engine.mu.Lock()
		if ctx.Err() != nil || network.Err() != nil || engine.closed || engine.networkEpoch.Load() != epoch {
			engine.mu.Unlock()
			return
		}
		state.err = ""
		if err != nil {
			state.err = err.Error() // keep serving the previous copy
			result.Failed++
		} else {
			result.Succeeded++
		}
		engine.mu.Unlock()
	}
	return result
}

func (engine *Engine) downloadRuleSet(ctx context.Context, url string) ([]byte, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return engine.Dial(ctx, "rule-set", address)
		},
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "HopWay")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxRuleSetSize {
		return nil, errors.New("rule set is larger than 32 MB")
	}
	return readRuleSet(ctx, response.Body)
}

func (engine *Engine) refreshRuleSet(ctx context.Context, state *ruleSetState, epoch uint64) error {
	ctx, cancel := context.WithTimeout(ctx, ruleSetDownloadDeadline)
	defer cancel()
	var (
		data    []byte
		updated time.Time
		err     error
	)
	if state.Path != "" {
		data, updated, err = readRuleSetFile(ctx, state.Path)
	} else {
		data, err = engine.downloadRuleSet(ctx, state.URL)
		updated = time.Now()
	}
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	// The refresh gate gives this call exclusive write access to the state.
	content := state.content
	if content == nil || digest != state.digest {
		content, err = ruleset.ParseContext(ctx, state.format, state.Behavior, data)
		if err != nil {
			return err
		}
	}
	if content.Entries == 0 {
		return errors.New("rule set has no usable entries")
	}
	cost := engine.ruleSetCost - state.content.MemoryCost() + content.MemoryCost()
	if cost > maxProfileRuleSetCost {
		return errRuleSetProfileBudget
	}
	path := engine.cachePath(state)
	var staged string
	if path != "" {
		staged, err = stageWrite(path, data)
		if err != nil {
			return fmt.Errorf("cache: %w", err)
		}
		defer os.Remove(staged)
	}
	// Disk I/O and parsing stay outside the routing lock. Only publishing the
	// prepared file and the new matcher are serialized with a network change.
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if engine.closed || engine.ctx.Err() != nil || engine.networkEpoch.Load() != epoch {
		return context.Canceled
	}
	if staged != "" {
		if err := os.Rename(staged, path); err != nil {
			return fmt.Errorf("cache: %w", err)
		}
	}
	if state.content != content {
		engine.rules.replaceRuleSet(state.slot, content)
		state.content, state.digest = content, digest
		engine.ruleSetCost = cost
	}
	state.updated = updated
	return nil
}

// WriteAtomic replaces path so a crash never leaves a half-written file.
func WriteAtomic(path string, data []byte) error {
	return WriteAtomicChecked(path, data, nil)
}

// WriteAtomicChecked runs check after staging, immediately before replacement.
func WriteAtomicChecked(path string, data []byte, check func() error) error {
	staged, err := stageWrite(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(staged)
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	return os.Rename(staged, path)
}

func stageWrite(path string, data []byte) (name string, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	return tmp.Name(), nil
}

func (engine *Engine) ruleSetStatus() []RuleSetStatus {
	var list []RuleSetStatus
	for _, state := range engine.ruleSets {
		status := RuleSetStatus{Name: state.Name, Error: state.err}
		if content := state.content; content != nil {
			status.Entries, status.Skipped = content.Entries, content.Skipped
		}
		if !state.updated.IsZero() {
			status.Updated = state.updated.UnixMilli()
		}
		list = append(list, status)
	}
	return list
}
