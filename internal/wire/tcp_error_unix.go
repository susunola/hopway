//go:build darwin || linux

package wire

import (
	"net"
	"syscall"
)

const tcpSocketErrorSupported = true

// pendingTCPError consumes an asynchronous socket failure. A clean FIN has
// no socket error and must still be handled by the normal relay read.
func pendingTCPError(conn *net.TCPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil
	}
	var failure error
	_ = raw.Control(func(fd uintptr) {
		code, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err == nil && code != 0 {
			failure = syscall.Errno(code)
		}
	})
	return failure
}
