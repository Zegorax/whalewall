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
	"go.uber.org/zap"
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

// TestUnregisterKeepsPolicyOfNewOwner: a container's address can be reused
// before the cleanup of the previous container runs. Removing the old
// policy must not take the new container's policy with it.
func TestUnregisterKeepsPolicyOfNewOwner(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: {recA}}))
	s, addr := newServer(t, up, time.Second)
	ip := []netip.Addr{netip.MustParseAddr("127.0.0.1")}

	oldPolicy := &Policy{Name: "old", Match: matchSuffix(policyZone), Allow: (&recorder{}).allow}
	newPolicy := &Policy{Name: "new", Match: matchSuffix(policyZone), Allow: (&recorder{}).allow}
	s.Register(ip, oldPolicy)
	s.Register(ip, newPolicy) // the address was reused
	s.Unregister(ip, oldPolicy)

	resp := query(t, netUDP, addr, "127.0.0.1", zoneA, dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeSuccess) // the new container still resolves

	s.Unregister(ip, newPolicy)
	resp = query(t, netUDP, addr, "127.0.0.1", zoneA, dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeRefused)

	s.Unregister(ip, nil) // nothing to remove, must not panic
}

// FuzzFilterAnswer feeds arbitrary messages, as an attacker controlled
// authoritative server could send them, to the answer filter. It must
// never panic and never return an address that is not in the answer
// section.
func FuzzFilterAnswer(f *testing.F) {
	seed := func(rrs ...string) {
		m := new(dns.Msg)
		m.SetQuestion(zoneA, dns.TypeA)
		for _, r := range rrs {
			rr, err := dns.NewRR(r)
			if err != nil {
				f.Fatal(err)
			}
			m.Answer = append(m.Answer, rr)
		}
		b, err := m.Pack()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	seed()
	seed(recA)
	seed(recA, recAAAA)
	seed("a.corp.test. 60 IN CNAME b.corp.test.", "b.corp.test. 60 IN A 10.0.0.2")
	seed("a.corp.test. 60 IN CNAME a.corp.test.")
	seed("a.corp.test. 4294967295 IN A 127.0.0.1", "a.corp.test. 0 IN A 169.254.169.254")
	seed("a.corp.test. 60 IN A 0.0.0.0", "a.corp.test. 60 IN AAAA ::", "a.corp.test. 60 IN AAAA ::ffff:10.0.0.1")

	s, err := New(zap.NewNop(), Config{Upstreams: []string{"127.0.0.1:1"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m := new(dns.Msg)
		if err := m.Unpack(b); err != nil {
			return
		}
		inAnswer := make(map[netip.Addr]bool)
		for _, rr := range m.Answer {
			switch rr := rr.(type) {
			case *dns.A:
				if a, ok := netip.AddrFromSlice(rr.A); ok {
					inAnswer[a.Unmap()] = true
				}
			case *dns.AAAA:
				if a, ok := netip.AddrFromSlice(rr.AAAA); ok {
					inAnswer[a.Unmap()] = true
				}
			}
		}
		for _, r := range s.filterAnswer(m, zoneA, nil) {
			if !inAnswer[r.Addr.Unmap()] {
				t.Fatalf("%v is not in the answer section", r.Addr)
			}
			if r.Addr.IsLoopback() || r.Addr.IsUnspecified() || r.Addr.IsLinkLocalUnicast() || r.Addr.IsMulticast() {
				t.Fatalf("%v must never be allowed", r.Addr)
			}
			if r.TTL <= 0 || r.TTL > s.cfg.MaxTTL+s.cfg.Grace {
				t.Fatalf("ttl %v out of range", r.TTL)
			}
		}
	})
}

// TestConcurrentRegistrationAndQueries runs policy changes, queries and
// connections at the same time; with -race this finds unsynchronized state.
func TestConcurrentRegistrationAndQueries(t *testing.T) {
	t.Parallel()

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: {recA}}))
	s, addr := newServer(t, up, time.Second)
	ip := []netip.Addr{netip.MustParseAddr("127.0.0.1")}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				p := &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: (&recorder{}).allow}
				s.Register(ip, p)
				time.Sleep(time.Millisecond)
				s.Unregister(ip, p)
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 60 {
				network := netUDP
				c := dns.Client{Net: network, Timeout: 200 * time.Millisecond}
				m := new(dns.Msg)
				m.SetQuestion(zoneA, dns.TypeA)
				_, _, _ = c.Exchange(m, addr.String())
				d, err := net.DialTimeout(netTCP, addr.String(), 200*time.Millisecond)
				if err == nil {
					_ = d.Close()
				}
			}
		}()
	}
	time.Sleep(1500 * time.Millisecond)
	close(stop)
	wg.Wait()
}
