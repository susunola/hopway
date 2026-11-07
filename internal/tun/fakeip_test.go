package tun

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var testFakeRange = netip.MustParsePrefix("198.18.0.0/29")

func TestFakeIPProtectsActiveAndRecentlyUsedLeases(t *testing.T) {
	fake := NewFakeIP(testFakeRange)
	now := time.Now()
	fake.now = func() time.Time { return now }
	first, second := fake.Allocate("first.test"), fake.Allocate("second.test")
	for _, name := range []string{"third.test", "fourth.test", "fifth.test"} {
		if address := fake.Allocate(name); !testFakeRange.Contains(address) {
			t.Fatalf("invalid lease for %s: %v", name, address)
		}
	}
	if name, release := fake.acquire(first); name != "first.test" || release == nil {
		t.Fatal("could not pin first lease")
	} else {
		defer release()
	}
	_, releaseSecondRef := fake.acquire(first)
	if address := fake.Allocate("new.test"); address.IsValid() {
		t.Fatalf("recent lease recycled: %v", address)
	}
	now = now.Add(fakeIPRetention + time.Second)
	if address := fake.Allocate("new.test"); address != second {
		t.Fatalf("expected first expired idle slot %v, got %v", second, address)
	}
	releaseSecondRef()
	for i := range 20 {
		now = now.Add(fakeIPRetention + time.Second)
		if address := fake.Allocate("cycle-" + strconv.Itoa(i) + ".test"); !address.IsValid() || address == first {
			t.Fatalf("could not recycle an idle slot beside the active connection: %v", address)
		}
		if name, ok := fake.Lookup(first); !ok || name != "first.test" {
			t.Fatalf("pinned lease changed: %q", name)
		}
	}
	stats := fake.Stats().IPv4
	if stats.Capacity != 5 || stats.Mapped != 5 || stats.Pinned != 1 || stats.Refused != 1 || stats.Reclaimed < 1 {
		t.Fatalf("unexpected pool status: %+v", stats)
	}
}

func TestFakeIPPoolFullConcurrentAllocationsStayUnique(t *testing.T) {
	fake := NewFakeIP(testFakeRange)
	addresses := make(chan netip.Addr, 100)
	var workers sync.WaitGroup
	for i := range 100 {
		workers.Go(func() {
			addresses <- fake.Allocate("domain-" + strconv.Itoa(i) + ".test")
		})
	}
	workers.Wait()
	close(addresses)
	seen := map[netip.Addr]bool{}
	for address := range addresses {
		if !address.IsValid() {
			continue
		}
		if seen[address] {
			t.Fatalf("two valid domains share %v", address)
		}
		seen[address] = true
	}
	if len(seen) != 5 || fake.Stats().IPv4.Refused != 95 {
		t.Fatalf("pool returned %d unique leases: %+v", len(seen), fake.Stats().IPv4)
	}
	query := new(dns.Msg).SetQuestion("overflow.test.", dns.TypeA)
	reply := fakeDNSResponse(t, query, fake)
	if reply.Rcode != dns.RcodeServerFailure || len(reply.Answer) != 0 {
		t.Fatalf("full pool should return SERVFAIL: %+v", reply)
	}
}

func TestFakeIPFamiliesExpireIndependently(t *testing.T) {
	fake := NewFakeIP(testFakeRange)
	fake.EnableIPv6(netip.MustParsePrefix("fc00::/126"))
	now := time.Now()
	fake.now = func() time.Time { return now }
	four := fake.Allocate("host.test")
	six := fake.Allocate6("host.test")
	now = now.Add(time.Minute)
	if fake.Allocate6("HOST.test.") != six {
		t.Fatal("AAAA refresh changed the address")
	}
	now = now.Add(time.Minute + time.Second)
	if _, ok := fake.Lookup(four); ok {
		t.Fatal("AAAA refresh extended A lifetime")
	}
	if name, ok := fake.Lookup(six); !ok || name != "host.test" {
		t.Fatalf("AAAA lost with A: %q", name)
	}
	_, release := fake.acquire(six)
	if release == nil {
		t.Fatal("could not hold valid IPv6 lease")
	}
	now = now.Add(fakeIPRetention + time.Second)
	release()
	if _, ok := fake.Lookup(six); !ok {
		t.Fatal("last flow close did not start a new retention window")
	}
	now = now.Add(fakeIPRetention + time.Second)
	if recycled := fake.Allocate6("other.test"); recycled != six {
		t.Fatalf("expired IPv6 slot was not available: %v", recycled)
	}
	if name, ok := fake.Lookup(six); !ok || name != "other.test" {
		t.Fatalf("reclaimed IPv6 slot maps to %q", name)
	}
}

func fakeDNSResponse(t *testing.T, query *dns.Msg, fake *FakeIP) *dns.Msg {
	t.Helper()
	data, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	data, err = answerDNS(context.Background(), data, fake, func(context.Context, []byte) ([]byte, error) {
		t.Fatalf("synthetic query leaked to upstream: %v", query.Question)
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(data); err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestFakeIPReverseAndReservedAddresses(t *testing.T) {
	fake := NewFakeIP(testFakeRange)
	fake.EnableIPv6(netip.MustParsePrefix("fc00::/126"))
	for _, address := range []netip.Addr{fake.Allocate("proxied.test"), fake.Allocate6("proxied.test")} {
		reverse, err := dns.ReverseAddr(address.String())
		if err != nil {
			t.Fatal(err)
		}
		reply := fakeDNSResponse(t, new(dns.Msg).SetQuestion(strings.ToUpper(reverse), dns.TypePTR), fake)
		if len(reply.Answer) != 1 || reply.Answer[0].(*dns.PTR).Ptr != "proxied.test." {
			t.Fatalf("reverse for %v: %v", address, reply.Answer)
		}
	}
	before := fake.Stats()
	for _, reserved := range []string{"198.18.0.0", "198.18.0.1", "198.18.0.7", "fc00::", "fc00::1", "fc00::3"} {
		reverse, _ := dns.ReverseAddr(reserved)
		for _, q := range []*dns.Msg{
			new(dns.Msg).SetQuestion(reverse, dns.TypePTR),
			new(dns.Msg).SetQuestion(reserved+".", dns.TypeA),
		} {
			reply := fakeDNSResponse(t, q, fake)
			if reply.Rcode != dns.RcodeNameError || len(reply.Answer) != 0 {
				t.Fatalf("reserved address got an answer: %v", reply)
			}
		}
	}
	if after := fake.Stats(); after.IPv4 != before.IPv4 || *after.IPv6 != *before.IPv6 {
		t.Fatalf("reserved address queries altered pools: %+v %+v", after.IPv4, *after.IPv6)
	}
}

func TestFakeIPConflictReportsBothNetworks(t *testing.T) {
	options := Options{}
	options.defaults()
	local := networkPrefix{netip.MustParsePrefix("198.19.10.0/24"), "网卡 test0"}
	err := options.fakeIPConflict([]networkPrefix{local})
	if err == nil || !strings.Contains(err.Error(), DefaultFakeRange.String()) ||
		!strings.Contains(err.Error(), local.prefix.String()) || !strings.Contains(err.Error(), "test0") {
		t.Fatalf("IPv4 conflict report: %v", err)
	}
	v6 := networkPrefix{netip.MustParsePrefix("fc00:1::/64"), "路由 test1"}
	if err := options.fakeIPConflict([]networkPrefix{v6}); err != nil {
		t.Fatalf("disabled pool should not block TUN: %v", err)
	}
	options.IPv6 = true
	if err := options.fakeIPConflict([]networkPrefix{v6}); err == nil || !strings.Contains(err.Error(), v6.prefix.String()) {
		t.Fatalf("IPv6 conflict report: %v", err)
	}
	options.Address = netip.MustParsePrefix("198.18.0.1/30")
	if err := options.fakeIPConflict(nil); err == nil {
		t.Fatal("overlap with virtual interface was accepted")
	}
}

func TestFakeIPNetworkPreflightReadsSystemRoutes(t *testing.T) {
	// Only inspect local state. An actual overlap is a valid result on a host
	// where a VPN is already using one of the fake ranges.
	if err := (Options{IPv6: true}).CheckFakeIPNetworks(); err != nil && !strings.Contains(err.Error(), "重叠") {
		t.Fatal(err)
	}
}

func TestFakeIPPreflightDetectsExistingInterfaceNetwork(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 2 || prefix.Bits() > 30 ||
				prefix.Overlaps(netip.MustParsePrefix("172.19.0.1/30")) {
				continue
			}
			options := Options{FakeRange: prefix.Masked()}
			err = options.CheckFakeIPNetworks()
			if err == nil || !strings.Contains(err.Error(), prefix.Masked().String()) ||
				!strings.Contains(err.Error(), "网卡") {
				t.Fatalf("missing conflict on existing IPv4 network: %v", err)
			}
			return
		}
	}
	t.Skip("no eligible interface network to check")
}

func BenchmarkFakeIPChurn(b *testing.B) {
	fake := NewFakeIP(netip.MustParsePrefix("198.18.0.0/20"))
	var tick, next, peak atomic.Int64
	start := time.Now()
	fake.now = func() time.Time { return start.Add(time.Duration(tick.Add(1)) * 50 * time.Millisecond) }
	sample := func() {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		for previous := peak.Load(); int64(stats.HeapAlloc) > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, int64(stats.HeapAlloc)) {
				break
			}
		}
	}
	sample()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n := next.Add(1)
			name := "host-" + strconv.FormatInt(n, 10) + ".test"
			addr := fake.Allocate(name)
			if got, release := fake.acquire(addr); release == nil {
				b.Error("allocation pressure left no lease")
			} else {
				if got != name {
					b.Error("lease routed to a different domain")
				}
				release()
			}
			if n%8192 == 0 {
				sample()
			}
		}
	})
	b.StopTimer()
	sample()
	stats := fake.Stats().IPv4
	b.ReportMetric(float64(stats.Reclaimed), "reclaims")
	b.ReportMetric(float64(stats.Refused), "refusals")
	b.ReportMetric(float64(peak.Load()), "peak-heap-B")
}
