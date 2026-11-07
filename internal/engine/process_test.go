//go:build !hopway_native && (darwin || linux)

package engine

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mac-proxy/internal/backend"
	"mac-proxy/internal/socks5"
)

// socksDial performs a minimal SOCKS5 CONNECT and returns the tunnel.
func socksDial(t *testing.T, proxy, target string) (net.Conn, byte) {
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	host, portText, _ := net.SplitHostPort(target)
	port, _ := net.LookupPort("tcp", portText)
	ip := net.ParseIP(host).To4()
	conn.Write([]byte{5, 1, 0})
	io.ReadFull(conn, make([]byte, 2))
	conn.Write(append(append([]byte{5, 1, 0, 1}, ip...), byte(port>>8), byte(port)))
	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	return conn, reply[1]
}

func serve(t *testing.T, core *Engine) string {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			client, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			go func() { defer client.Close(); socks5.Handle(client, core.Dial) }()
		}
	}()
	return listener.Addr().String()
}

func TestProcessAttribution(t *testing.T) {
	self, _ := os.Executable()
	echo := echoServer(t)

	// A process rule decides the route: the lookup happens before dialing.
	config := Default()
	config.Rules = []Rule{{Type: RuleProcessName, Value: filepath.Base(self), Via: "REJECT"}, {Type: RuleMatch, Via: "DIRECT"}}
	core, err := New(config, backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	conn, code := socksDial(t, serve(t, core), echo)
	conn.Close()
	last := core.Status().Connections[0]
	if last.Process == "" {
		t.Skip("kernel connection table not readable here")
	}
	if code == 0 || last.State != "blocked" || last.Process != filepath.Base(self) || last.Rule != "process-name "+filepath.Base(self) {
		t.Fatalf("reply %d, record %+v", code, last)
	}

	// No process rule: the connection is not delayed, the owner is filled in later.
	plain, err := New(Default(), backend.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	conn, code = socksDial(t, serve(t, plain), echo)
	if code != 0 {
		t.Fatalf("reply %d", code)
	}
	roundTrip(t, conn, "attributed")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && plain.Status().Connections[0].Process == "" {
		time.Sleep(10 * time.Millisecond)
	}
	conn.Close()
	time.Sleep(50 * time.Millisecond)
	if record := plain.Status().Connections[0]; record.Process != filepath.Base(self) || record.ProcessPath == "" {
		t.Fatalf("record %+v", record)
	}
}
