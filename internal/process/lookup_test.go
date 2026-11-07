//go:build !hopway_native && (darwin || linux)

package process

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLookupOwnSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			defer conn.Close()
			buffer := make([]byte, 1)
			conn.Read(buffer)
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	server := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	owner, err := Lookup(client, server)
	if err != nil {
		t.Skipf("kernel connection table not readable here: %v", err)
	}
	self, _ := os.Executable()
	if (owner.PID != 0 && owner.PID != uint32(os.Getpid())) || filepath.Base(owner.Path) != filepath.Base(self) {
		t.Fatalf("got %+v, want pid %d path %s", owner, os.Getpid(), self)
	}
}

func TestBundleName(t *testing.T) {
	for path, want := range map[string]string{
		"/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)": "Google Chrome",
		"/usr/bin/curl": "",
		"/Applications/Telegram.app/Contents/MacOS/Telegram": "Telegram",
	} {
		if got := BundleName(path); got != want {
			t.Errorf("%s: got %q want %q", path, got, want)
		}
	}
}
