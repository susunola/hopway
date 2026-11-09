//go:build !hopway_native && (darwin || linux)

package tun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceMetadataDetectsAStaleHelper(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "hopway")
	if err := os.WriteFile(executable, []byte("build one"), 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := BinaryDigest(executable)
	if err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(dir, "service.json")
	data, err := json.Marshal(ServiceMetadata{Version: ServiceVersion, SHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if serviceOutdatedAt(metaPath, executable) {
		t.Fatal("a matching metadata file must not look stale")
	}

	// A rebuilt app has a different digest; the helper must be reinstalled.
	if err := os.WriteFile(executable, []byte("build two"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !serviceOutdatedAt(metaPath, executable) {
		t.Fatal("a changed binary must be reported as outdated")
	}

	// An old installer wrote no metadata; treat that as outdated too.
	if !serviceOutdatedAt(filepath.Join(dir, "missing.json"), executable) {
		t.Fatal("missing metadata must be reported as outdated")
	}
}

func TestServiceMetadataVersionMismatchIsOutdated(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "hopway")
	if err := os.WriteFile(executable, []byte("build"), 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := BinaryDigest(executable)
	if err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(dir, "service.json")
	data, err := json.Marshal(ServiceMetadata{Version: ServiceVersion - 1, SHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if !serviceOutdatedAt(metaPath, executable) {
		t.Fatal("an older protocol version must be reported as outdated")
	}
}
