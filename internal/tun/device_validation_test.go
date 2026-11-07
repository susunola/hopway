//go:build !hopway_native && (darwin || linux)

package tun

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStartRejectsAndClosesOrdinaryFileDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "not-a-tun")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if svc, err := Start(Options{FD: fd}, nil, nil); err == nil {
		svc.Close()
		t.Fatal("started a TUN with an ordinary file descriptor")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("rejected descriptor stayed open: %v", err)
	}
}
