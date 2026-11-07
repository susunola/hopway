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

// Watch calls notify on each change until ctx ends. fingerprint and clock
// are injectable for tests.
func Watch(ctx context.Context, interval time.Duration, fingerprint func() string, notify func(Event)) {
	if fingerprint == nil {
		fingerprint = Fingerprint
	}
	last := fingerprint()
	wall, mono := time.Now().Round(0), time.Now()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		nowWall, nowMono := time.Now().Round(0), time.Now()
		// While asleep the monotonic clock stands still but the wall clock
		// does not, so a large gap between them means we just woke up.
		if gap := nowWall.Sub(wall) - nowMono.Sub(mono); gap > 5*time.Second+interval {
			notify(Event{Kind: "wake", At: nowWall, Info: "slept about " + gap.Round(time.Second).String()})
		}
		wall, mono = nowWall, nowMono
		if current := fingerprint(); current != last {
			last = current
			notify(Event{Kind: "network", At: nowWall})
		}
	}
}
