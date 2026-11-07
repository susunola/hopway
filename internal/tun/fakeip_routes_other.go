//go:build !darwin

package tun

func routedNetworks(map[int]string) ([]networkPrefix, error) {
	return nil, nil
}
