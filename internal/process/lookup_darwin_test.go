//go:build !hopway_native && darwin && cgo

package process

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCachedOwnerRejectsReusedPIDAndDescriptor(t *testing.T) {
	key := socketKey{unix.IPPROTO_TCP, netip.MustParseAddrPort("127.0.0.1:53000"), netip.MustParseAddrPort("127.0.0.1:1080")}
	socket := socketIdentity{pid: uint32(os.Getpid()), generation: 30}
	stamp := processStamp{startSec: 100, path: "/old/Browser.app/Contents/MacOS/Browser", uid: uint32(os.Getuid())}
	now := time.Unix(200, 0)
	discoveries, scans := 0, 0
	live := true
	lookup := socketOwnerLookup{
		cache: make(map[socketKey]cachedOwner),
		discover: func(socketKey) (socketIdentity, error) {
			discoveries++
			if !live {
				return socketIdentity{}, errUnknownSocket
			}
			return socket, nil
		},
		findFD: func(socketIdentity, int) int { scans++; return 9 },
		matchFD: func(candidate socketIdentity, fd, protocol int) bool {
			return live && fd == 9 && protocol == unix.IPPROTO_TCP && candidate == socket
		},
		stamp:    func(uint32) (processStamp, error) { return stamp, nil },
		bundleID: func(path string) string { return path },
		now:      func() time.Time { return now },
	}
	first, err := lookup.lookup(key)
	if err != nil || first.Path != stamp.path {
		t.Fatalf("initial owner: %+v, %v", first, err)
	}
	for range 10 {
		owner, err := lookup.lookup(key)
		if err != nil || owner != first {
			t.Fatalf("cache hit: %+v, %v", owner, err)
		}
	}
	if discoveries != 1 || scans != 1 {
		t.Fatalf("warm lookup repeated expensive scans: table %d, fd %d", discoveries, scans)
	}

	// Same tuple and numeric PID after exit, with the descriptor number
	// reused by a different process and kernel socket.
	live = false
	if owner, err := lookup.lookup(key); owner != nil || !errors.Is(err, errUnknownSocket) {
		t.Fatalf("exited owner was returned: %+v, %v", owner, err)
	}
	live = true
	socket.generation++
	stamp.startSec++
	stamp.path = "/new/Other.app/Contents/MacOS/Other"
	second, err := lookup.lookup(key)
	if err != nil || second.Path != stamp.path || second.PID != first.PID || second == first {
		t.Fatalf("reused numeric PID: %+v, %v", second, err)
	}
	// Even with the same live descriptor, a changed process startup stamp
	// or executable path must invalidate the cached metadata.
	stamp.startUsec++
	if owner, err := lookup.lookup(key); err != nil || owner == second {
		t.Fatalf("process generation did not invalidate cache: %+v, %v", owner, err)
	}
	now = now.Add(ownerCacheTTL)
	before := scans
	if _, err := lookup.lookup(key); err != nil || scans != before+1 {
		t.Fatalf("cache entry did not expire: scans %d, %v", scans, err)
	}
}

func TestDarwinVerifiesOwnTCPAndUDPSocket(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1:0"
			if network[len(network)-1] == '6' {
				host = "[::1]:0"
			}
			var source, target net.Addr
			var client net.Conn
			protocol := unix.IPPROTO_TCP
			switch network[:3] {
			case "tcp":
				listener, err := net.Listen(network, host)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { listener.Close() })
				conn, err := net.Dial(network, listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				client = conn
				source, target = conn.LocalAddr(), conn.RemoteAddr()
			case "udp":
				protocol = unix.IPPROTO_UDP
				listener, err := net.ListenPacket(network, host)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { listener.Close() })
				conn, err := net.Dial(network, listener.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				client = conn
				source, target = conn.LocalAddr(), conn.RemoteAddr()
			}
			key := socketKey{protocol, socketAddrPort(t, source), socketAddrPort(t, target)}
			socket, err := darwinOwners.discover(key)
			if err != nil {
				t.Fatalf("kernel socket lookup: %v", err)
			}
			if socket.pid != uint32(os.Getpid()) || socket.generation == 0 {
				t.Fatalf("unexpected live socket %+v", socket)
			}
			fd := darwinOwners.findFD(socket, protocol)
			if fd < 0 {
				t.Fatalf("kernel descriptor did not match socket generation %d", socket.generation)
			}
			owner, err := darwinOwners.lookup(key)
			if err != nil || owner.PID != uint32(os.Getpid()) {
				t.Fatalf("lookup returned %v, %v", owner, err)
			}
			for range 5 {
				hit, err := darwinOwners.lookup(key)
				if err != nil || hit != owner {
					t.Fatalf("live socket did not reuse its owner: %v, %v", hit, err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if stale, err := darwinOwners.lookup(key); stale != nil || err == nil {
				t.Fatalf("closed socket returned an owner: %v, %v", stale, err)
			}
		})
	}
}

func TestDarwinUnconnectedUDPDoesNotGuessSharedPort(t *testing.T) {
	options := net.ListenConfig{Control: func(_, _ string, conn syscall.RawConn) error {
		var setErr error
		if err := conn.Control(func(fd uintptr) {
			setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); err != nil {
			return err
		}
		return setErr
	}}
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	first, err := options.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	target := socketAddrPort(t, receiver.LocalAddr())
	source := netip.AddrPortFrom(target.Addr(), socketAddrPort(t, first.LocalAddr()).Port())
	if _, err := first.WriteTo([]byte("first"), receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if owner, err := LookupUDP(source, target); err != nil || owner.PID != uint32(os.Getpid()) {
		t.Fatalf("single UDP sender: %v, %v", owner, err)
	}
	second, err := options.ListenPacket(context.Background(), "udp4", first.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := second.WriteTo([]byte("second"), receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if owner, err := LookupUDP(source, target); owner != nil || !errors.Is(err, errUnknownSocket) {
		t.Fatalf("shared UDP port must be unidentified: %v, %v", owner, err)
	}
}

func TestDarwinVerifiesAnotherProcessSocket(t *testing.T) {
	if address := os.Getenv("HOPWAY_TEST_PEER_ADDRESS"); address != "" {
		conn, err := net.Dial("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestDarwinVerifiesAnotherProcessSocket$")
	child.Env = append(os.Environ(), "HOPWAY_TEST_PEER_ADDRESS="+listener.Addr().String())
	pipe, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		pipe.Close()
		child.Wait()
	}()
	listener.SetDeadline(time.Now().Add(4 * time.Second))
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	key := socketKey{unix.IPPROTO_TCP, socketAddrPort(t, peer.RemoteAddr()), socketAddrPort(t, peer.LocalAddr())}
	socket, err := darwinOwners.discover(key)
	if err != nil || socket.pid != uint32(child.Process.Pid) {
		t.Fatalf("socket discovery: %+v, %v, child pid %d", socket, err, child.Process.Pid)
	}
	stamp, err := darwinOwners.stamp(socket.pid)
	if err != nil {
		t.Fatalf("process lookup: %v", err)
	}
	if fd := darwinOwners.findFD(socket, key.protocol); fd < 0 {
		t.Fatalf("descriptor lookup: %+v", socket)
	}
	owner, err := darwinOwners.lookup(key)
	if err != nil || owner.PID != socket.pid || owner.Path != stamp.path {
		t.Fatalf("external owner: %+v, %v", owner, err)
	}
}

func socketAddrPort(t *testing.T, address net.Addr) netip.AddrPort {
	t.Helper()
	value, err := netip.ParseAddrPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	return normalizedAddrPort(value)
}
