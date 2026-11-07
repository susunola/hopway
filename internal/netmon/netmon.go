// Package netmon notices network changes and sleep/wake without platform
// hooks: it compares interface addresses, and the wall clock against the
// monotonic clock (which stops while a Mac sleeps).
package netmon

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

type Event struct {
	Kind string    `json:"kind"` // "network" or "wake"
	At   time.Time `json:"at"`
	Info string    `json:"info,omitempty"`
}

// Fingerprint describes the usable network: up, non-loopback interfaces and
// their unicast addresses (link-local IPv6 excluded, it changes on its own).
func Fingerprint() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var parts []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			parts = append(parts, iface.Name+"="+ipnet.IP.String())
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// Watch calls notify on each change until ctx ends. fingerprint is injectable for tests.
func Watch(ctx context.Context, interval time.Duration, fingerprint func() string, notify func(Event)) {
	if fingerprint == nil {
		fingerprint = Fingerprint
	}
	last := fingerprint()
	mono := time.Now()
	wall := mono.Round(0)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := time.Now()
		nowWall := now.Round(0)
		current := fingerprint()
		changed := current != last
		// Both events trigger the same reset. On wake, consume any
		// accompanying address change so the engine only resets once.
		gap := nowWall.Sub(wall) - now.Sub(mono)
		wall, mono, last = nowWall, now, current
		if gap > 5*time.Second+interval {
			notify(Event{Kind: "wake", At: nowWall, Info: "slept about " + gap.Round(time.Second).String()})
		} else if changed {
			notify(Event{Kind: "network", At: nowWall})
		}
	}
}
