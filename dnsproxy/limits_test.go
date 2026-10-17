package dnsproxy

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/miekg/dns"
)

func newLimitedServer(t *testing.T, up *fakeUpstream, mod func(*Config)) (*Server, netip.AddrPort) {
	t.Helper()

	cfg := Config{
		Upstreams: []string{up.addr},
		MinTTL:    time.Second,
		Grace:     time.Second,
		Timeout:   time.Second,
	}
	mod(&cfg)
	s, err := New(testLogger(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	addr := acquireFree(t, s)
	t.Cleanup(s.Close)

	return s, addr
}

// openConns opens n TCP connections from src to addr and returns the ones
// the server keeps open.
func openConns(t *testing.T, addr netip.AddrPort, src string, n int) (kept []net.Conn, total int) {
	t.Helper()

	all := make([]net.Conn, 0, n)
	for range n {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: time.Second}
		c, err := d.Dial("tcp", addr.String())
		if err != nil {
			continue
		}
		all = append(all, c)
	}
	t.Cleanup(func() {
		for _, c := range all {
			_ = c.Close()
		}
	})

	// a connection the server closed returns EOF at once, one that is
	// kept waits for a query
	for _, c := range all {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 1)
		_, err := c.Read(buf)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			kept = append(kept, c)
		}
	}

	return kept, len(all)
}

func TestUnmanagedTCPConnectionsAreClosedAtOnce(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: {recA}}))
	s, addr := newLimitedServer(t, up, func(*Config) {})
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: (&recorder{}).allow})

	// 127.0.0.9 has no policy: holding connections open is not possible
	kept, total := openConns(t, addr, "127.0.0.9", 50)
	is.True(total > 0)
	is.Equal(len(kept), 0) // the server closed every connection of the unmanaged source
}

func TestTCPConnectionsPerSourceAreCapped(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: {recA}}))
	s, addr := newLimitedServer(t, up, func(c *Config) {
		c.MaxTCPConnsPerSource = 4
	})
	rec := &recorder{}
	pol := &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: rec.allow}
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.3")}, pol)

	kept, _ := openConns(t, addr, "127.0.0.1", 200)
	is.True(len(kept) <= 4) // the flood is capped
	is.True(len(kept) > 0)  // but the source can still use its share

	// another container is not affected by the flood
	resp := query(t, netTCP, addr, "127.0.0.3", zoneA, dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)

	// the slots are free again once the connections are closed
	for _, c := range kept {
		_ = c.Close()
	}
	time.Sleep(200 * time.Millisecond)
	resp = query(t, netTCP, addr, "127.0.0.1", zoneA, dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
}

func TestQueryRateIsLimitedPerSource(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: {recA}}))
	s, addr := newLimitedServer(t, up, func(c *Config) {
		c.QueryRate = 5
		c.QueryBurst = 10
	})
	pol := &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: (&recorder{}).allow}
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.3")}, pol)

	var wg sync.WaitGroup
	for range 300 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := dns.Client{Net: netUDP, Timeout: 300 * time.Millisecond, Dialer: &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}}}
			m := new(dns.Msg)
			m.SetQuestion(zoneA, dns.TypeA)
			_, _, _ = c.Exchange(m, addr.String())
		}()
	}
	wg.Wait()

	// the flood reached the upstream only in the amount the limit allows
	is.True(up.queries.Load() <= 20)
	is.True(up.queries.Load() >= 5)

	// and the other source is served at once
	resp := query(t, netUDP, addr, "127.0.0.3", zoneA, dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
}

func TestInflightQueriesArePerSourceBounded(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	// an upstream that never answers keeps every query in flight
	release := make(chan struct{})
	up := newFakeUpstream(t, func(dns.ResponseWriter, *dns.Msg) { <-release })
	t.Cleanup(func() { close(release) })
	s, addr := newLimitedServer(t, up, func(c *Config) {
		c.MaxInflight = 8
		c.QueryRate = 10000
		c.QueryBurst = 10000
		c.Timeout = 2 * time.Second
	})
	pol := &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: (&recorder{}).allow}
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, pol)

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := dns.Client{Net: netUDP, Timeout: 500 * time.Millisecond}
			m := new(dns.Msg)
			m.SetQuestion(zoneA, dns.TypeA)
			_, _, _ = c.Exchange(m, addr.String())
		}()
	}
	wg.Wait()

	is.True(up.queries.Load() <= 8) // no more upstream queries than the limit
}
