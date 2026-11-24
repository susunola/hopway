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
//
// A Wi-Fi switch usually shows up over several ticks (the old address goes
// away, then the new one arrives), and each tick would reset the engine on
// its own. Changes are held until the fingerprint has been stable for a short
// window, so one switch produces one reset. A wake-up consumes any
// accompanying address change for the same reason.
func Watch(ctx context.Context, interval time.Duration, fingerprint func() string, notify func(Event)) {
	if fingerprint == nil {
		fingerprint = Fingerprint
	}
	if interval <= 0 {
		interval = time.Second
	}
	settle := interval * 3 / 2
	if maxSettle := 5 * time.Second; settle > maxSettle {
		settle = maxSettle
	}
	last := fingerprint()
	mono := time.Now()
	wall := mono.Round(0)
	var pending time.Time // first tick that saw a change, zero when settled
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
		gap := nowWall.Sub(wall) - now.Sub(mono)
		wall, mono, last = nowWall, now, current
		if gap > 5*time.Second+interval {
			pending = time.Time{}
			notify(Event{Kind: "wake", At: nowWall, Info: "slept about " + gap.Round(time.Second).String()})
			continue
		}
		if changed {
			if pending.IsZero() {
				pending = now
			}
			continue
		}
		if !pending.IsZero() && now.Sub(pending) >= settle {
			pending = time.Time{}
			notify(Event{Kind: "network", At: nowWall})
		}
	}
}
