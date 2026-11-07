package backend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var (
	oldDNSAddr = netip.MustParseAddr("192.0.2.1")
	newDNSAddr = netip.MustParseAddr("198.51.100.2")
)

func lookupWithin(t testing.TB, c *cache, host string) ([]netip.Addr, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return c.Lookup(ctx, host)
}

func TestDNSConcurrentLookupsShareFlightAndAllowOtherHosts(t *testing.T) {
	const requests = 100
	unblock := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(unblock) })
	var calls atomic.Int32
	c := newCache(func() lookupIP {
		return func(ctx context.Context, host string) ([]netip.Addr, error) {
			if host == "other.test." {
				return []netip.Addr{newDNSAddr}, nil
			}
			calls.Add(1)
			select {
			case <-unblock:
				return []netip.Addr{oldDNSAddr}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}, 10)
	results := make(chan error, requests)
	for i := range requests {
		go func() {
			host := "Same.Test."
			if i%2 == 0 {
				host = "same.test"
			}
			addrs, err := lookupWithin(t, c, host)
			if err == nil && (len(addrs) != 1 || addrs[0] != oldDNSAddr) {
				err = fmt.Errorf("unexpected addresses: %v", addrs)
			}
			results <- err
		}()
	}
	deadline := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		p := c.view.pending["same.test."]
		ready := p != nil && p.waiters == requests
		c.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("requests did not join the same flight")
		}
		time.Sleep(time.Millisecond)
	}
	if addrs, err := lookupWithin(t, c, "other.test"); err != nil || len(addrs) != 1 || addrs[0] != newDNSAddr {
		t.Fatalf("unrelated lookup waited for a slow query: %v, %v", addrs, err)
	}
	release.Do(func() { close(unblock) })
	for range requests {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	addrs, err := lookupWithin(t, c, "SAME.TEST.")
	if err != nil || len(addrs) != 1 || addrs[0] != oldDNSAddr || calls.Load() != 1 {
		t.Fatalf("100 callers and warm lookup: %v, %v, upstream calls %d", addrs, err, calls.Load())
	}
	addrs[0] = newDNSAddr
	if cached, _ := lookupWithin(t, c, "same.test"); cached[0] != oldDNSAddr {
		t.Fatalf("caller mutated cached answer: %v", cached)
	}
}

func TestDNSFlushDiscardsLateAnswer(t *testing.T) {
	started, unblock := make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(unblock) })
	generation := 0
	c := newCache(func() lookupIP {
		generation++
		if generation == 1 {
			return func(context.Context, string) ([]netip.Addr, error) {
				close(started)
				<-unblock // simulate an old DNS view that replies after cancellation
				return []netip.Addr{oldDNSAddr}, nil
			}
		}
		return func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{newDNSAddr}, nil
		}
	}, 10)
	old := make(chan error, 1)
	go func() {
		_, err := lookupWithin(t, c, "switch.test")
		old <- err
	}()
	<-started
	c.mu.Lock()
	first := c.view.pending["switch.test."]
	c.mu.Unlock()
	c.Pin("pin.test", []netip.Addr{oldDNSAddr})
	c.Flush()
	if err := <-old; !errors.Is(err, context.Canceled) {
		t.Fatalf("old lookup error = %v", err)
	}
	checkNew := func() {
		t.Helper()
		if addrs, err := lookupWithin(t, c, "switch.test"); err != nil || len(addrs) != 1 || addrs[0] != newDNSAddr {
			t.Fatalf("DNS view after switch: %v, %v", addrs, err)
		}
	}
	checkNew()
	release.Do(func() { close(unblock) })
	<-first.done
	checkNew()
	if addrs, err := lookupWithin(t, c, "PIN.TEST."); err != nil || len(addrs) != 1 || addrs[0] != oldDNSAddr {
		t.Fatalf("fixed answer lost on flush: %v, %v", addrs, err)
	}
}

func TestDNSCacheDistinguishesMissingAndTemporary(t *testing.T) {
	var missing, failing atomic.Int32
	c := newCache(func() lookupIP {
		return func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "missing.test." {
				missing.Add(1)
				return nil, &net.DNSError{IsNotFound: true, Err: "no such host"}
			}
			if failing.Add(1) == 1 {
				return nil, &net.DNSError{IsTemporary: true, Err: "server misbehaving"}
			}
			return []netip.Addr{newDNSAddr}, nil
		}
	}, 10)
	for range 2 {
		_, err := lookupWithin(t, c, "missing.test.")
		var failure *net.DNSError
		if !errors.As(err, &failure) || !failure.IsNotFound {
			t.Fatalf("missing lookup error: %v", err)
		}
	}
	if missing.Load() != 1 {
		t.Fatalf("miss was not cached: %d calls", missing.Load())
	}
	if _, err := lookupWithin(t, c, "failing.test"); err == nil {
		t.Fatal("expected temporary error")
	}
	if addrs, err := lookupWithin(t, c, "failing.test"); err != nil || len(addrs) != 1 || addrs[0] != newDNSAddr {
		t.Fatalf("temporary failure prevented recovery: %v, %v", addrs, err)
	}
}

func TestDNSCacheEvictsLeastRecentlyUsed(t *testing.T) {
	var hotCalls atomic.Int32
	c := newCache(func() lookupIP {
		return func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "hot.test." {
				hotCalls.Add(1)
			}
			return []netip.Addr{newDNSAddr}, nil
		}
	}, dnsCacheLimit)
	for i := range dnsCacheLimit + 100 {
		if _, err := lookupWithin(t, c, "hot.test"); err != nil {
			t.Fatal(err)
		}
		if _, err := lookupWithin(t, c, fmt.Sprintf("entry-%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.view.entries) != dnsCacheLimit || c.view.entries["entry-0.test."] != nil || hotCalls.Load() != 1 {
		t.Fatalf("LRU: %d entries, hot host queried %d times", len(c.view.entries), hotCalls.Load())
	}
}

func TestDNSCanceledCallerDoesNotCancelAnotherWaiter(t *testing.T) {
	unblock := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(unblock) })
	c := newCache(func() lookupIP {
		return func(ctx context.Context, _ string) ([]netip.Addr, error) {
			select {
			case <-unblock:
				return []netip.Addr{oldDNSAddr}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, second := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := c.Lookup(ctx, "shared.test")
		first <- err
	}()
	go func() {
		_, err := lookupWithin(t, c, "shared.test")
		second <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		p := c.view.pending["shared.test."]
		ready := p != nil && p.waiters == 2
		c.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("requests did not join the same flight")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller error: %v", err)
	}
	release.Do(func() { close(unblock) })
	if err := <-second; err != nil {
		t.Fatalf("remaining caller lost the shared answer: %v", err)
	}
}

func TestDNSRelativeNameKeepsSearchSuffixFallback(t *testing.T) {
	c := newCache(func() lookupIP {
		return func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "site.dev" {
				return []netip.Addr{newDNSAddr}, nil
			}
			return nil, &net.DNSError{IsNotFound: true, Err: "no such host"}
		}
	}, 10)
	if addrs, err := lookupWithin(t, c, "site.dev"); err != nil || len(addrs) != 1 || addrs[0] != newDNSAddr {
		t.Fatalf("search result: %v, %v", addrs, err)
	}
	if _, err := lookupWithin(t, c, "site.dev."); err == nil {
		t.Fatal("search suffix answer leaked into absolute lookup")
	}
}

func TestBoundDNSChangesUpstreamView(t *testing.T) {
	server := func(answer netip.Addr) string {
		t.Helper()
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ready := make(chan struct{})
		upstream := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(ready) },
			Handler: dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
				reply := new(dns.Msg).SetReply(query)
				q := query.Question[0]
				if q.Qtype == dns.TypeA {
					reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{
						Name: q.Name, Class: dns.ClassINET, Rrtype: dns.TypeA, Ttl: 600,
					}, A: net.IP(answer.AsSlice())}}
				}
				_ = w.WriteMsg(reply)
			})}
		go upstream.ActivateAndServe()
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("DNS fixture failed to start")
		}
		t.Cleanup(func() { _ = upstream.Shutdown() })
		return conn.LocalAddr().String()
	}
	first, second := server(oldDNSAddr), server(newDNSAddr)
	bind := func(string, string, syscall.RawConn) error { return nil }
	defer SetSocketControl(nil)
	for _, view := range []struct {
		upstream string
		want     netip.Addr
	}{{first, oldDNSAddr}, {second, newDNSAddr}} {
		SetSocketControl(bind, view.upstream)
		addrs, err := lookupWithin(t, Resolver, "switch.test.")
		if err != nil || len(addrs) != 1 || addrs[0] != view.want {
			t.Fatalf("bound resolver got %v, %v, want %s", addrs, err, view.want)
		}
	}
	SetSocketControl(bind, "resolve-me.example:53")
	if servers := UpstreamDNS(); len(servers) != 0 {
		t.Fatalf("recursive DNS bootstrap accepted: %v", servers)
	}
}
