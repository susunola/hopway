//go:build linux

package tun

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDeviceHandoff(t *testing.T) {
	path, listener, cleanup, err := helperSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	file, _ := os.CreateTemp(t.TempDir(), "device")
	file.WriteString("payload")
	go func() {
		if err := SendDevice(path, int(file.Fd()), "utun7"); err != nil {
			t.Error(err)
		}
	}()
	fd, name, err := ReceiveDevice(listener, 5*time.Second, nil)
	if err != nil || name != "utun7" {
		t.Fatalf("%v %q", err, name)
	}
	defer unix.Close(fd)
	buffer := make([]byte, 7)
	if n, _ := unix.Pread(fd, buffer, 0); string(buffer[:n]) != "payload" {
		t.Fatalf("received descriptor does not refer to the file: %q", buffer[:n])
	}
	abort := make(chan error, 1)
	abort <- nil
	if _, _, err := ReceiveDevice(listener, 5*time.Second, abort); err == nil {
		t.Fatal("abort must end the wait")
	}
}
