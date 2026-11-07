package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"mac-proxy/internal/engine"
	"mac-proxy/internal/importer"
	"mac-proxy/internal/usage"
)

const (
	healthInterval  = time.Minute
	usageInterval   = 10 * time.Second
	refreshInterval = 6 * time.Hour
)

// managedCore bundles the services that only run under -managed: health
// checks, usage history, config reload and subscription refresh.
type managedCore struct {
	core       *engine.Engine
	configPath string
	history    *usage.History
	refreshMu  sync.Mutex
}

// RefreshReport lists, per subscription, whether it refreshed and why not.
type RefreshReport struct {
	Updated []string          `json:"updated"`
	Failed  map[string]string `json:"failed"`
	Notes   []string          `json:"notes"`
}

func usagePath(configPath, flagValue string) string {
	if flagValue != "" || configPath == "" {
		return flagValue
	}
	return filepath.Join(filepath.Dir(configPath), "usage.json")
}

func (managed *managedCore) start(ctx context.Context) {
	go managed.core.RunHealthChecks(ctx, healthInterval)
	go func() {
		ticker := time.NewTicker(usageInterval)
		defer ticker.Stop()
		saves := 0
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				managed.record(now)
				if saves++; saves%6 == 0 {
					managed.save()
				}
			}
		}
	}()
	go func() {
		for {
			managed.refreshDue(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Minute):
			}
		}
	}()
}

func (managed *managedCore) record(now time.Time) {
	if managed.history != nil {
		managed.history.Record(managed.core.Traffic(), now)
	}
}

func (managed *managedCore) save() {
	if managed.history == nil {
		return
	}
	if err := managed.history.Save(); err != nil {
		log.Printf("save usage history: %v", err)
	}
}

// stop flushes the usage history before the core exits.
func (managed *managedCore) stop() {
	managed.record(time.Now())
	managed.save()
}

// reload rereads the config file and applies it to the running core.
func (managed *managedCore) reload() error {
	if managed.configPath == "" {
		return errors.New("core was started without -config")
	}
	config, err := loadConfig(managed.configPath)
	if err != nil {
		return err
	}
	managed.record(time.Now())
	return managed.core.Reload(config)
}

// refreshDue refreshes subscriptions that have not updated for refreshInterval.
func (managed *managedCore) refreshDue(ctx context.Context) {
	if managed.configPath == "" {
		return
	}
	config, err := loadConfig(managed.configPath)
	if err != nil {
		return
	}
	var due []string
	for _, plan := range config.Subscriptions {
		if time.Since(time.Unix(plan.Updated, 0)) >= refreshInterval {
			due = append(due, plan.Name)
		}
	}
	if len(due) == 0 {
		return
	}
	report, err := managed.refresh(ctx, due)
	if err != nil {
		log.Printf("refresh subscriptions: %v", err)
	} else if len(report.Failed) != 0 {
		log.Printf("refresh subscriptions: %v", report.Failed)
	}
}

// refresh downloads the named subscriptions (all when names is empty),
// writes the config file and applies it to the running core.
func (managed *managedCore) refresh(ctx context.Context, names []string) (RefreshReport, error) {
	managed.refreshMu.Lock()
	defer managed.refreshMu.Unlock()
	report, err := refreshFile(ctx, managed.configPath, names)
	if err != nil || len(report.Updated) == 0 {
		return report, err
	}
	return report, managed.reload()
}

// refreshFile refreshes subscriptions in the config at path and rewrites it.
// It is shared by -refresh and the managed core.
func refreshFile(ctx context.Context, path string, names []string) (RefreshReport, error) {
	report := RefreshReport{Updated: []string{}, Failed: map[string]string{}, Notes: []string{}}
	if path == "" {
		return report, errors.New("refresh needs -config")
	}
	config, err := loadConfig(path)
	if err != nil {
		return report, err
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	for _, plan := range config.Subscriptions {
		if len(names) != 0 && !wanted[plan.Name] {
			continue
		}
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		result, err := importer.Import(attempt, strings.NewReader(plan.URL), config)
		cancel()
		if err != nil {
			report.Failed[plan.Name] = err.Error()
			continue
		}
		config = result.Config
		report.Updated = append(report.Updated, plan.Name)
		report.Notes = append(report.Notes, result.Notes...)
	}
	if len(names) != 0 {
		for name := range wanted {
			if !contains(report.Updated, name) && report.Failed[name] == "" {
				report.Failed[name] = "没有这个订阅"
			}
		}
	}
	if len(report.Updated) == 0 {
		return report, nil
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return report, err
	}
	return report, usage.WriteFileAtomic(path, append(data, '\n'))
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func dayCount(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	count, err := strconv.Atoi(raw)
	if err != nil || count < 0 {
		return 0, fmt.Errorf("days must be a non-negative integer")
	}
	return count, nil
}

func runRefresh(path string) error {
	report, err := refreshFile(context.Background(), path, nil)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}
