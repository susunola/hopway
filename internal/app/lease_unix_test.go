//go:build darwin || linux

package app

import (
	"errors"
	"testing"

	"mac-proxy/internal/backend"
)

func TestProfileLeaseProtectsLiveCore(t *testing.T) {
	dir := t.TempDir()
	first, err := Open("", dir, backend.Native{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if other, err := Open("", dir, backend.Native{}); !errors.Is(err, ErrProfileInUse) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("same profile allowed concurrently: %v", err)
	}
	first.Close()
	next, err := Open("", dir, backend.Native{})
	if err != nil {
		t.Fatalf("failed to reopen after close: %v", err)
	}
	next.Close()
}
