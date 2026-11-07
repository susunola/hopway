//go:build darwin || linux

package tun

import (
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// SendDevice passes a device file descriptor and its name over a Unix
// socket (SCM_RIGHTS). The privileged helper uses it.
func SendDevice(socketPath string, fd int, name string) error {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, _, err = conn.WriteMsgUnix([]byte(name), unix.UnixRights(fd), nil)
	return err
}

// ReceiveDevice waits on listener for one descriptor from SendDevice.
// abort stops the wait early (the helper failed or the user cancelled).
func ReceiveDevice(listener *net.UnixListener, timeout time.Duration, abort <-chan error) (int, string, error) {
	type result struct {
		fd   int
		name string
		err  error
	}
	results := make(chan result, 1)
	go func() {
		listener.SetDeadline(time.Now().Add(timeout))
		conn, err := listener.AcceptUnix()
		if err != nil {
			results <- result{err: err}
			return
		}
		defer conn.Close()
		name := make([]byte, 64)
		oob := make([]byte, unix.CmsgSpace(4))
		n, oobn, _, _, err := conn.ReadMsgUnix(name, oob)
		if err != nil {
			results <- result{err: err}
			return
		}
		messages, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(messages) != 1 {
			results <- result{err: errors.New("helper sent no device")}
			return
		}
		fds, err := unix.ParseUnixRights(&messages[0])
		if err != nil || len(fds) != 1 {
			results <- result{err: errors.New("helper sent no device")}
			return
		}
		results <- result{fd: fds[0], name: string(name[:n])}
	}()
	select {
	case r := <-results:
		return r.fd, r.name, r.err
	case err := <-abort:
		listener.Close()
		if err == nil {
			err = errors.New("the helper exited without creating the device")
		}
		return 0, "", err
	}
}

// helperSocket makes a private directory for the hand-off socket.
func helperSocket() (string, *net.UnixListener, func(), error) {
	dir, err := os.MkdirTemp("", "hopway-tun-")
	if err != nil {
		return "", nil, nil, err
	}
	path := dir + "/helper.sock"
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		os.RemoveAll(dir)
		return "", nil, nil, err
	}
	// The root helper must be able to connect; the directory stays private.
	os.Chmod(dir, 0o711)
	return path, listener, func() { listener.Close(); os.RemoveAll(dir) }, nil
}

func unixRights(fd int) []byte { return unix.UnixRights(fd) }
func closeFD(fd int)           { unix.Close(fd) }

// receiveRights reads one message that may carry a descriptor.
func receiveRights(conn *net.UnixConn) (int, []byte, error) {
	data := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(data, oob)
	if err != nil {
		return 0, nil, err
	}
	fd := 0
	if messages, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil && len(messages) == 1 {
		if fds, err := unix.ParseUnixRights(&messages[0]); err == nil && len(fds) == 1 {
			fd = fds[0]
		}
	}
	return fd, data[:n], nil
}

func dialRaw(path string) (*net.UnixConn, error) {
	return net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
}
