//go:build !hopway_native && (darwin || linux)

package tun

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestServicePassesCustomMTUToDeviceFactory(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "hw-mtu-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "service")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	file, err := os.CreateTemp(t.TempDir(), "device-fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fileFD := int(file.Fd())
	captured := make(chan Options, 1)
	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := listener.AcceptUnix()
		if err == nil {
			serveRequest(conn, uint32(os.Geteuid()), func(options Options) (int, string, error) {
				captured <- options
				fd, err := unix.Dup(fileFD)
				return fd, "utun-fixture", err
			})
		}
	}()
	defer func() {
		listener.Close()
		<-served
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	fd, _, err := OpenWithService(ctx, socket, Options{MTU: 1400, IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if options := <-captured; options.MTU != 1400 || !options.IPv6 {
		t.Fatalf("unexpected device options: %+v", options)
	}
}
