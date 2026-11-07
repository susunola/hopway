//go:build unix

package profile

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// LockWrites serializes changes to the profile and its subscription snapshots.
func LockWrites(dataDir string) (func(), error) {
	dir := filepath.Join(dataDir, "subscriptions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, ".write.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return func() { _ = file.Close() }, nil
}
