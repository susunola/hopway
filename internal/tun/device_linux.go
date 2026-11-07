//go:build !hopway_native

package tun

import (
	"errors"

	"golang.org/x/sys/unix"
)

func verifyDevice(fd int, expected string) error {
	ifr, _ := unix.NewIfreq("")
	if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil {
		return err
	}
	if ifr.Uint16()&unix.IFF_TUN == 0 || (expected != "" && ifr.Name() != expected) {
		return errors.New("invalid TUN device or name")
	}
	return nil
}
