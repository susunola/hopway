//go:build !unix

package profile

import "sync"

var snapshotWrites sync.Mutex

// LockWrites serializes changes to the profile and its subscription snapshots.
func LockWrites(string) (func(), error) {
	snapshotWrites.Lock()
	return snapshotWrites.Unlock, nil
}
