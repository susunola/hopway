package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mac-proxy/internal/engine"
)

func TestRestoreLastGoodReplacesBrokenProfileAndKeepsIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	dataDir := filepath.Join(dir, "cache")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	good := `{"socksPort":1080,"httpPort":8080,"mode":"rule","selected":"DIRECT","nodes":[],"rules":[{"type":"match","via":"DIRECT"}]}`
	if err := engine.WriteAtomic(lastGoodPath(dataDir), []byte(good)); err != nil {
		t.Fatal(err)
	}
	broken := []byte(`{"socksPort": 1080,`)
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}

	backup, err := RestoreLastGood(path, dataDir, func(engine.Config) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil || string(restored) != good {
		t.Fatalf("restored %q, %v", restored, err)
	}
	if backup == "" {
		t.Fatal("the broken file was not backed up")
	}
	saved, err := os.ReadFile(backup)
	if err != nil || string(saved) != string(broken) {
		t.Fatalf("backup holds %q, %v", saved, err)
	}
}

func TestRestoreLastGoodRefusesInvalidBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	dataDir := filepath.Join(dir, "cache")
	os.MkdirAll(dataDir, 0o700)
	if err := engine.WriteAtomic(lastGoodPath(dataDir), []byte(`{"socksPort": 1,`)); err != nil {
		t.Fatal(err)
	}
	current := []byte(`{"socksPort":1080,"httpPort":8080,"mode":"rule","selected":"DIRECT"}`)
	os.WriteFile(path, current, 0o600)

	if _, err := RestoreLastGood(path, dataDir, func(engine.Config) error { return nil }); err == nil {
		t.Fatal("an unparsable last-good file must be refused")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(current) {
		t.Fatal("a refused restore must leave the configuration untouched")
	}
}

func TestRestoreLastGoodWithoutBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if _, err := RestoreLastGood(path, filepath.Join(dir, "cache"), func(engine.Config) error { return nil }); err == nil ||
		!strings.Contains(err.Error(), "上一次可用") {
		t.Fatalf("missing backup was not reported: %v", err)
	}
}
