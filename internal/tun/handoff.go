//go:build darwin || linux

package tun

import (
	"context"
	"errors"
	"net"
	"os"

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

// receiveDevice takes ownership of the listener and bounds both the accept
// and read phases, including when a peer connects without sending a descriptor.
func receiveDevice(ctx context.Context, listener *net.UnixListener, requireRoot bool) (int, string, error) {
	defer listener.Close()
	stopAccept := context.AfterFunc(ctx, func() { listener.Close() })
	defer stopAccept()
	conn, err := listener.AcceptUnix()
	if err != nil {
		if ctx.Err() != nil {
			return 0, "", context.Cause(ctx)
		}
		return 0, "", err
	}
	stopAccept()
	defer conn.Close()
	if requireRoot {
		uid, err := peerUID(conn)
		if err != nil {
			return 0, "", err
		}
		if uid != 0 {
			return 0, "", errors.New("the TUN helper connection is not privileged")
		}
	}
	stopRead := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopRead()
	fd, data, err := receiveRights(conn)
	if ctx.Err() != nil {
		if fd > 0 {
			closeFD(fd)
		}
		return 0, "", context.Cause(ctx)
	}
	if err != nil {
		return 0, "", err
	}
	if fd <= 0 || len(data) == 0 || len(data) > 64 {
		if fd > 0 {
			closeFD(fd)
		}
		return 0, "", errors.New("helper sent no valid device")
	}
	return fd, string(data), nil
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
	n, oobn, flags, _, err := conn.ReadMsgUnix(data, oob)
	if err != nil {
		return 0, nil, err
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, err
	}
	var fds []int
	for i := range messages {
		rights, err := unix.ParseUnixRights(&messages[i])
		if err == nil {
			fds = append(fds, rights...)
		}
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(fds) > 1 {
		for _, fd := range fds {
			closeFD(fd)
		}
		return 0, nil, errors.New("invalid descriptor message")
	}
	if len(fds) == 1 {
		// FD zero is reserved in Options to mean opening a new device.
		if fds[0] == 0 {
			closeFD(0)
			return 0, nil, errors.New("invalid device descriptor")
		}
		unix.CloseOnExec(fds[0])
		return fds[0], data[:n], nil
	}
	return 0, data[:n], nil
}

func dialRaw(path string) (*net.UnixConn, error) {
	return net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
}
