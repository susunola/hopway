//go:build darwin || linux

package tun

import (
	"context"
	"errors"
	"io"
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
	file, err := os.CreateTemp(t.TempDir(), "device")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("payload"); err != nil {
		t.Fatal(err)
	}
	if err := SendDevice(path, int(file.Fd()), "utun7"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	fd, name, err := receiveDevice(ctx, listener, false)
	if err != nil || name != "utun7" {
		t.Fatalf("%v %q", err, name)
	}
	defer unix.Close(fd)
	buffer := make([]byte, 7)
	if n, _ := unix.Pread(fd, buffer, 0); string(buffer[:n]) != "payload" {
		t.Fatalf("received descriptor does not refer to the file: %q", buffer[:n])
	}
}

func TestDeviceHandoffStopsForSilentPeer(t *testing.T) {
	path, listener, cleanup, err := helperSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	peer, err := dialRaw(path)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := receiveDevice(ctx, listener, false)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handoff got stuck waiting on the peer")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("peer was not closed: %d, %v", n, err)
	}
}
