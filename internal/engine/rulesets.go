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
	ruleSetCheck            = 10 * time.Minute
	ruleSetDownloadDeadline = 60 * time.Second
)

type ruleSetState struct {
	RuleSet
	set     *ruleset.Set
	format  string
	updated time.Time
	err     string
}

func (engine *Engine) openRuleSets(config Config) (map[string]*ruleset.Set, error) {
	sets := map[string]*ruleset.Set{}
	for _, rs := range config.RuleSets {
		if rs.Name == "" || sets[rs.Name] != nil {
			return nil, fmt.Errorf("invalid or duplicate rule-set name %q", rs.Name)
		}
		if (rs.URL == "") == (rs.Path == "") {
			return nil, fmt.Errorf("rule-set %q needs exactly one of url or path", rs.Name)
		}
		if rs.URL != "" && !strings.HasPrefix(rs.URL, "https://") && !strings.HasPrefix(rs.URL, "http://") {
			return nil, fmt.Errorf("rule-set %q url must be http or https", rs.Name)
		}
		if rs.Interval != 0 && rs.Interval < 600 {
			return nil, fmt.Errorf("rule-set %q interval must be at least 600 seconds", rs.Name)
		}
		state := &ruleSetState{RuleSet: rs, set: ruleset.NewSet(rs.Name), format: rs.Format}
		if state.format == "" {
			state.format = ruleset.DetectFormat(rs.URL + rs.Path)
		}
		if state.Interval == 0 {
			state.Interval = defaultRuleSetInterval
		}
		switch state.format {
		case ruleset.FormatSRS, ruleset.FormatYAML, ruleset.FormatText:
		default:
			return nil, fmt.Errorf("rule-set %q has unknown format %q", rs.Name, rs.Format)
		}
		if rs.Path != "" {
			data, err := os.ReadFile(rs.Path)
			if err != nil {
				return nil, fmt.Errorf("rule-set %q: %w", rs.Name, err)
			}
			content, err := ruleset.Parse(state.format, rs.Behavior, data)
			if err != nil {
				return nil, fmt.Errorf("rule-set %q: %w", rs.Name, err)
			}
			state.set.Store(content)
			state.updated = time.Now()
		} else if path := engine.cachePath(state); path != "" {
			if data, err := os.ReadFile(path); err == nil {
				if content, err := ruleset.Parse(state.format, rs.Behavior, data); err == nil {
					state.set.Store(content)
					if info, err := os.Stat(path); err == nil {
						state.updated = info.ModTime()
					}
				}
			}
		}
		sets[rs.Name] = state.set
		engine.ruleSets = append(engine.ruleSets, state)
	}
	return sets, nil
}

func (engine *Engine) cachePath(state *ruleSetState) string {
	if engine.dataDir == "" || state.URL == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(state.URL + "\x00" + state.format + "\x00" + state.Behavior))
	return filepath.Join(engine.dataDir, "rulesets", hex.EncodeToString(sum[:8])+"."+state.format)
}

func (engine *Engine) ruleSetLoop(ctx context.Context) {
	for {
		engine.RefreshRuleSets(ctx, false)
		select {
		case <-ctx.Done():
			return
		case <-time.After(ruleSetCheck):
		}
	}
}

// RefreshRuleSets downloads remote sets that are stale (or all, if force).
func (engine *Engine) RefreshRuleSets(ctx context.Context, force bool) {
	engine.ruleRefreshMu.Lock()
	defer engine.ruleRefreshMu.Unlock()
	engine.mu.Lock()
	network, epoch := engine.networkCtx, engine.networkEpoch.Load()
	engine.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if network != nil {
		stop := context.AfterFunc(network, cancel)
		defer stop()
	}
	for _, state := range engine.ruleSets {
		if ctx.Err() != nil || (network != nil && network.Err() != nil) {
			return
		}
		engine.mu.Lock()
		stale := state.URL != "" && (force || state.set.Load() == nil ||
			time.Since(state.updated) > time.Duration(state.Interval)*time.Second)
		engine.mu.Unlock()
		if !stale {
			continue
		}
		err := engine.downloadRuleSet(ctx, state, epoch)
		engine.mu.Lock()
		if ctx.Err() != nil || engine.closed || engine.networkEpoch.Load() != epoch {
			engine.mu.Unlock()
			return
		}
		state.err = ""
		if err != nil {
			state.err = err.Error() // keep serving the previous copy
		}
		engine.mu.Unlock()
	}
}

func (engine *Engine) downloadRuleSet(ctx context.Context, state *ruleSetState, epoch uint64) error {
	ctx, cancel := context.WithTimeout(ctx, ruleSetDownloadDeadline)
	defer cancel()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return engine.Dial(ctx, "rule-set", address)
		},
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, state.URL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "HopWay")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxRuleSetSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxRuleSetSize {
		return errors.New("rule set is larger than 32 MB")
	}
	content, err := ruleset.Parse(state.format, state.Behavior, data)
	if err != nil {
		return err
	}
	if content.Entries == 0 {
		return errors.New("rule set has no usable entries")
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
	if engine.closed || engine.networkEpoch.Load() != epoch {
		return context.Canceled
	}
	if staged != "" {
		if err := os.Rename(staged, path); err != nil {
			return fmt.Errorf("cache: %w", err)
		}
	}
	state.set.Store(content)
	state.updated = time.Now()
	return nil
}

// WriteAtomic replaces path so a crash never leaves a half-written file.
func WriteAtomic(path string, data []byte) error {
	staged, err := stageWrite(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(staged)
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
		if content := state.set.Load(); content != nil {
			status.Entries, status.Skipped = content.Entries, content.Skipped
		}
		if !state.updated.IsZero() {
			status.Updated = state.updated.UnixMilli()
		}
		list = append(list, status)
	}
	return list
}
