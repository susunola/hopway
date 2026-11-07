//go:build !unix

package profile

import "context"

var snapshotWrites = make(chan struct{}, 1)

// LockWrites serializes changes to the profile and its subscription snapshots.
func LockWrites(dataDir string) (func(), error) {
	return LockWritesContext(context.Background(), dataDir)
}

func LockWritesContext(ctx context.Context, _ string) (func(), error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case snapshotWrites <- struct{}{}:
		return func() { <-snapshotWrites }, nil
	}
}
