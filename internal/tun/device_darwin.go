//go:build !hopway_native

package tun

import (
	"errors"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func verifyDevice(fd int, expected string) error {
	const systemControl, utunInterfaceName = 2, 2
	name, err := unix.GetsockoptString(fd, systemControl, utunInterfaceName)
	if err != nil {
		return err
	}
	number, ok := strings.CutPrefix(name, "utun")
	if _, err := strconv.ParseUint(number, 10, 32); !ok || err != nil || (expected != "" && name != expected) {
		return errors.New("invalid utun device or name")
	}
	return nil
}
