package profile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mac-proxy/internal/engine"
)

const snapshotGracePeriod = 24 * time.Hour

// PruneSnapshots cleans old cache files while the profile write lock is held.
// Only the app's managed profile directory is eligible. Keep references from
// saved and paused subscriptions, rollback, and other JSON profiles nearby.
func PruneSnapshots(path, dataDir string) error {
	if path == "" || dataDir == "" || filepath.Base(path) != "config.json" ||
		filepath.Clean(dataDir) != filepath.Join(filepath.Dir(path), "cache") {
		return nil
	}
	directory := filepath.Join(dataDir, "subscriptions")
	for _, dir := range []string{dataDir, directory} {
		info, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("订阅缓存路径必须是普通目录")
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-snapshotGracePeriod)
	var expired []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !snapshotFilename(entry.Name()) {
			continue
		}
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() && info.ModTime().Before(cutoff) {
			expired = append(expired, entry.Name())
		}
	}
	if len(expired) == 0 {
		return nil
	}
	retained := make(map[string]bool)
	if err := retainProfileSnapshots(lastGoodPath(dataDir), dataDir, retained); err != nil {
		return err
	}
	profiles, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	for _, entry := range profiles {
		name := entry.Name()
		if entry.IsDir() || strings.HasSuffix(name, ".lock") || strings.HasPrefix(name, ".tmp-") {
			continue
		}
		if strings.ToLower(filepath.Ext(name)) != ".json" {
			return nil // A differently named CLI profile might also use this cache.
		}
		if err := retainProfileSnapshots(filepath.Join(filepath.Dir(path), name), dataDir, retained); err != nil {
			return err // An unreadable profile might still refer to an old file.
		}
	}
	for _, name := range expired {
		if !retained[name] {
			if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func snapshotFilename(name string) bool {
	stem, ok := strings.CutSuffix(name, ".json")
	if !ok {
		return false
	}
	prefix, key, hasKey := strings.Cut(stem, "-")
	_, err := hex.DecodeString(prefix)
	return len(prefix) == 16 && err == nil && (!hasKey || validSnapshotKey(key))
}

func retainProfileSnapshots(path, dataDir string, retained map[string]bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("发现无法识别的配置文件")
	}
	// Other JSON files such as traffic history may be large and do not
	// describe profiles. Keep the scan bounded and fail closed.
	const maxProfileScan = 8 << 20
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxProfileScan+1))
	if err != nil {
		return err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || len(data) > maxProfileScan || !json.Valid(data) {
		return errors.New("发现无法读取的配置版本，已保留订阅缓存")
	}
	if data[0] != '{' {
		return nil
	}
	var references struct {
		Subscriptions []engine.Subscription `json:"subscriptions"`
	}
	if err := json.Unmarshal(data, &references); err != nil {
		return err
	}
	for _, sub := range references.Subscriptions {
		retained[filepath.Base(SnapshotPath(dataDir, sub))] = true
	}
	return nil
}
