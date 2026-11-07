//go:build !unix

package profile

import "sync"

var snapshotWrites sync.Mutex

func lockSnapshots(string) (func(), error) {
	snapshotWrites.Lock()
	return snapshotWrites.Unlock, nil
}
