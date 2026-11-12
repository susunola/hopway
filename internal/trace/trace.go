// Package trace carries per-connection timing between the engine and the
// protocol backend, so failures can be attributed to a specific stage.
package trace

import (
	"context"
	"sync"
	"time"
)

// Stage names, in the order a proxied connection passes through them.
const (
	StageRoute     = "route"     // rule matching / policy refused the request
	StageDNS       = "dns"       // resolving the server (or the target, for DIRECT)
	StageConnect   = "connect"   // TCP connect / UDP socket to the server
	StageHandshake = "handshake" // TLS, QUIC and proxy-protocol handshake
	StageUpstream  = "upstream"  // the proxy accepted us but the target never answered
)

type Trace struct {
	mu        sync.Mutex
	Server    string        // address the backend actually dialed
	DNSName   string        // dns server that answered the lookup (empty for literal IPs)
	DNS       time.Duration // time spent resolving Server
	Connect   time.Duration // time spent connecting to the resolved address
	Reached   bool          // a socket to the server was established
	FailStage string
	Reused    bool // a multiplexed session was reused, no socket was opened
}

type key struct{}

func With(ctx context.Context) (context.Context, *Trace) {
	t := &Trace{}
	return context.WithValue(ctx, key{}, t), t
}

func From(ctx context.Context) *Trace {
	t, _ := ctx.Value(key{}).(*Trace)
	return t
}

// Dial records one dial of the server. Only the first dial of a connection
// is recorded; QUIC port hopping and retries do not overwrite it.
func (t *Trace) Dial(server string, dns, connect time.Duration, stage string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Server != "" {
		return
	}
	t.Server, t.DNS, t.Connect = server, dns, connect
	t.Reached = stage == ""
	t.FailStage = stage
}

func (t *Trace) Snapshot() (server string, dns, connect time.Duration, reached bool, stage string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.Server, t.DNS, t.Connect, t.Reached, t.FailStage
}

// SetDNSServer remembers which configured server resolved the host, so the
// connection detail can show the upstream instead of guessing.
func (t *Trace) SetDNSServer(name string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.DNSName = name
	t.mu.Unlock()
}

func (t *Trace) DNSServerName() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.DNSName
}

// Dialed reports whether the backend opened a socket at all for this trace.
func (t *Trace) Dialed() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.Server != ""
}
