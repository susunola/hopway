//go:build unix

package profile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// LockWrites serializes changes to the profile and its subscription snapshots.
func LockWrites(dataDir string) (func(), error) {
	return LockWritesContext(context.Background(), dataDir)
}

func LockWritesContext(ctx context.Context, dataDir string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir := filepath.Join(dataDir, "subscriptions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, ".write.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var ticker *time.Ticker
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = file.Close() }, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			break
		}
		if ticker == nil {
			ticker = time.NewTicker(15 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	file.Close()
	return nil, err
}
