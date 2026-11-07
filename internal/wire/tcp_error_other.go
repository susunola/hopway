//go:build !darwin && !linux

package wire

import "net"

const tcpSocketErrorSupported = false

func pendingTCPError(*net.TCPConn) error { return nil }
