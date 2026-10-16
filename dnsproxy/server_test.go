package dnsproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/miekg/dns"
	"go.uber.org/zap/zaptest"
)

const (
	zoneA      = "a.corp.test."
	clientName = "client"
	recA       = "a.corp.test. 60 IN A 10.0.0.1"
	recAAAA    = "a.corp.test. 60 IN AAAA fd00::1"
)

// fakeUpstream is an authoritative DNS server for tests.
type fakeUpstream struct {
	addr    string
	queries atomic.Int32
}

func newFakeUpstream(t *testing.T, handler func(w dns.ResponseWriter, req *dns.Msg)) *fakeUpstream {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeUpstream{addr: addr}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		f.queries.Add(1)
		handler(w, req)
	})
	udpStarted := make(chan struct{})
	tcpStarted := make(chan struct{})
	udp := &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: func() { close(udpStarted) }}
	tcp := &dns.Server{Listener: ln, Handler: h, NotifyStartedFunc: func() { close(tcpStarted) }}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	<-udpStarted
	<-tcpStarted
	t.Cleanup(func() {
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
	})

	return f
}

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type recorder struct {
	mtx   sync.Mutex
	calls [][]Resolved
	// order records "allow" and "reply" events
	err error
}

func (r *recorder) allow(_ context.Context, _ string, addrs []Resolved) error {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.calls = append(r.calls, addrs)
	return r.err
}

func (r *recorder) all() []Resolved {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	var all []Resolved
	for _, c := range r.calls {
		all = append(all, c...)
	}
	return all
}

func freeAddr(t *testing.T, ip string) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", ip+":0")
	if err != nil {
		t.Skipf("can't listen on %s: %v", ip, err)
	}
	defer pc.Close()
	udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected address type %T", pc.LocalAddr())
	}
	port := udpAddr.Port
	return netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(port))
}

func matchSuffix(suffix string) func(string) bool {
	return func(name string) bool {
		return name == suffix || strings.HasSuffix(name, "."+suffix)
	}
}

func query(t *testing.T, network string, srv netip.AddrPort, src string, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := dns.Client{Net: network, Timeout: 2 * time.Second}
	if src != "" {
		switch network {
		case "udp":
			c.Dialer = &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(src)}}
		case "tcp":
			c.Dialer = &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
		}
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	resp, _, err := c.Exchange(m, srv.String())
	if err != nil {
		t.Fatalf("query %s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return resp
}

func newServer(t *testing.T, up *fakeUpstream, minTTL time.Duration) (*Server, netip.AddrPort) {
	t.Helper()
	s, err := New(zaptest.NewLogger(t), Config{
		Upstreams: []string{up.addr},
		MinTTL:    minTTL,
		Grace:     time.Second,
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t, "127.0.0.1")
	if err := s.Acquire(addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	return s, addr
}

func zoneHandler(t *testing.T, records map[string][]string) func(dns.ResponseWriter, *dns.Msg) {
	t.Helper()

	return func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		name := strings.ToLower(req.Question[0].Name)
		rrs, ok := records[name]
		if !ok {
			resp.Rcode = dns.RcodeNameError
		}
		for _, s := range rrs {
			r := rr(t, s)
			if r.Header().Rrtype == req.Question[0].Qtype || r.Header().Rrtype == dns.TypeCNAME {
				resp.Answer = append(resp.Answer, r)
			}
		}
		_ = w.WriteMsg(resp)
	}
}

func TestAllowedAndDenied(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		zoneA:              {recA, recAAAA},
		"evil.other.test.": {"evil.other.test. 60 IN A 10.0.0.9"},
	}))
	s, addr := newServer(t, up, time.Second)

	rec := &recorder{}
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, &Policy{
		Name:    clientName,
		Match:   matchSuffix("corp.test"),
		HasIPv6: true,
		Allow:   rec.allow,
	})

	// allowed name
	resp := query(t, "udp", addr, "", "A.Corp.Test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
	is.Equal(len(resp.Answer), 1)
	is.Equal(len(rec.all()), 1)
	is.Equal(rec.all()[0].Addr, netip.MustParseAddr("10.0.0.1"))
	// TTL is the 60s record TTL plus grace
	is.Equal(rec.all()[0].TTL, 61*time.Second)

	// AAAA answered for a container with IPv6
	resp = query(t, "udp", addr, "", "a.corp.test", dns.TypeAAAA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
	is.Equal(len(resp.Answer), 1)
	is.Equal(rec.all()[1].Addr, netip.MustParseAddr("fd00::1"))

	// same over TCP
	resp = query(t, "tcp", addr, "", "a.corp.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
	is.Equal(len(resp.Answer), 1)

	// denied name is never forwarded
	before := up.queries.Load()
	resp = query(t, "udp", addr, "", "evil.other.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeNameError)
	is.Equal(len(resp.Answer), 0)
	is.Equal(up.queries.Load(), before)

	// non-existent allowed name is passed through
	resp = query(t, "udp", addr, "", "nope.corp.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeNameError)
}

func TestUnknownSourceRefused(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		zoneA: {recA},
	}))
	s, addr := newServer(t, up, time.Second)

	rec := &recorder{}
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.2")}, &Policy{
		Name: clientName, Match: matchSuffix("corp.test"), Allow: rec.allow,
	})

	resp := query(t, "udp", addr, "127.0.0.1", "a.corp.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeRefused)
	is.Equal(up.queries.Load(), int32(0))

	resp = query(t, "udp", addr, "127.0.0.2", "a.corp.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)

	// after unregistering the source is refused again
	s.Unregister([]netip.Addr{netip.MustParseAddr("127.0.0.2")})
	resp = query(t, "udp", addr, "127.0.0.2", "a.corp.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeRefused)
}

func TestPerSourcePolicy(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		"a.one.test.": {"a.one.test. 60 IN A 10.0.1.1"},
		"a.two.test.": {"a.two.test. 60 IN A 10.0.2.1"},
	}))
	s, addr := newServer(t, up, time.Second)

	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, &Policy{
		Name: "one", Match: matchSuffix("one.test"), Allow: (&recorder{}).allow,
	})
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.2")}, &Policy{
		Name: "two", Match: matchSuffix("two.test"), Allow: (&recorder{}).allow,
	})

	is.Equal(query(t, "udp", addr, "127.0.0.1", "a.one.test", dns.TypeA).Rcode, dns.RcodeSuccess)
	is.Equal(query(t, "udp", addr, "127.0.0.1", "a.two.test", dns.TypeA).Rcode, dns.RcodeNameError)
	is.Equal(query(t, "udp", addr, "127.0.0.2", "a.two.test", dns.TypeA).Rcode, dns.RcodeSuccess)
	is.Equal(query(t, "udp", addr, "127.0.0.2", "a.one.test", dns.TypeA).Rcode, dns.RcodeNameError)
}

func TestCNAMEChain(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up2 := newFakeUpstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		for _, s := range []string{
			"alias.corp.test. 60 IN CNAME mid.cdn.example.",
			"mid.cdn.example. 60 IN CNAME edge.cdn.example.",
			"edge.cdn.example. 30 IN A 10.9.9.9",
			"other.example. 30 IN A 10.8.8.8",
		} {
			resp.Answer = append(resp.Answer, rr(t, s))
		}
		resp.Extra = append(resp.Extra, rr(t, "glue.example. 30 IN A 10.7.7.7"))
		_ = w.WriteMsg(resp)
	})
	s, addr := newServer(t, up2, 10*time.Second)

	rec := &recorder{}
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, &Policy{
		Name: clientName, Match: matchSuffix("corp.test"), Allow: rec.allow,
	})

	resp := query(t, "udp", addr, "", "alias.corp.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
	// only the chain starting at the question is kept
	is.Equal(len(resp.Answer), 3)
	is.Equal(len(resp.Extra), 0)
	all := rec.all()
	is.Equal(len(all), 1)
	is.Equal(all[0].Addr, netip.MustParseAddr("10.9.9.9"))
	// record TTL (30s) is above the minimum (10s), plus 1s grace
	is.Equal(all[0].TTL, 31*time.Second)
}

func TestMinTTLAndUnsafeAddresses(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		zoneA: {
			"a.corp.test. 0 IN A 10.0.0.1",
			"a.corp.test. 60 IN A 127.0.0.1",
			"a.corp.test. 60 IN A 169.254.169.254",
			"a.corp.test. 60 IN A 0.0.0.0",
		},
		"lo.corp.test.": {"lo.corp.test. 60 IN A 127.0.0.1"},
	}))
	s, addr := newServer(t, up, 20*time.Second)

	rec := &recorder{}
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, &Policy{
		Name: clientName, Match: matchSuffix("corp.test"), Allow: rec.allow,
	})

	resp := query(t, "udp", addr, "", "a.corp.test", dns.TypeA)
	is.Equal(len(resp.Answer), 1) // only the safe address is returned
	all := rec.all()
	is.Equal(len(all), 1)
	is.Equal(all[0].Addr, netip.MustParseAddr("10.0.0.1"))
	is.Equal(all[0].TTL, 21*time.Second) // min TTL + grace

	// an answer with only unsafe addresses opens nothing
	resp = query(t, "udp", addr, "", "lo.corp.test", dns.TypeA)
	is.Equal(len(resp.Answer), 0)
	is.Equal(len(rec.all()), 1)
}

func TestAAAAWithoutIPv6(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		zoneA: {recAAAA},
	}))
	s, addr := newServer(t, up, time.Second)

	rec := &recorder{}
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, &Policy{
		Name: clientName, Match: matchSuffix("corp.test"), HasIPv6: false, Allow: rec.allow,
	})

	resp := query(t, "udp", addr, "", "a.corp.test", dns.TypeAAAA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
	is.Equal(len(resp.Answer), 0)
	is.Equal(up.queries.Load(), int32(0))
	is.Equal(len(rec.all()), 0)
}

func TestAllowFailureFailsQuery(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		zoneA: {recA},
	}))
	s, addr := newServer(t, up, time.Second)

	rec := &recorder{err: errors.New("nftables unavailable")}
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, &Policy{
		Name: clientName, Match: matchSuffix("corp.test"), Allow: rec.allow,
	})

	resp := query(t, "udp", addr, "", "a.corp.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeServerFailure)
	is.Equal(len(resp.Answer), 0)
}

func TestAllowCalledBeforeReply(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		zoneA: {recA},
	}))
	s, addr := newServer(t, up, time.Second)

	release := make(chan struct{})
	entered := make(chan struct{})
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, &Policy{
		Name:  "client",
		Match: matchSuffix("corp.test"),
		Allow: func(ctx context.Context, _ string, _ []Resolved) error {
			close(entered)
			<-release
			return nil
		},
	})

	done := make(chan *dns.Msg, 1)
	go func() {
		done <- query(t, "udp", addr, "", "a.corp.test", dns.TypeA)
	}()
	<-entered
	select {
	case <-done:
		t.Fatal("reply was sent before the firewall was updated")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	resp := <-done
	is.Equal(resp.Rcode, dns.RcodeSuccess)
}

func TestTruncatedUDPRetriesOverTCP(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
			resp.Truncated = true
		} else {
			resp.Answer = append(resp.Answer, rr(t, recA))
		}
		_ = w.WriteMsg(resp)
	})
	s, addr := newServer(t, up, time.Second)

	rec := &recorder{}
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, &Policy{
		Name: clientName, Match: matchSuffix("corp.test"), Allow: rec.allow,
	})

	resp := query(t, "udp", addr, "", "a.corp.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
	is.Equal(len(resp.Answer), 1)
	is.Equal(up.queries.Load(), int32(2))
}

func TestUpstreamFailover(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	bad := newFakeUpstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(resp)
	})
	good := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		zoneA: {recA},
	}))
	s, err := New(zaptest.NewLogger(t), Config{
		Upstreams: []string{bad.addr, good.addr},
		Timeout:   time.Second,
	})
	is.NoErr(err)
	addr := freeAddr(t, "127.0.0.1")
	is.NoErr(s.Acquire(addr))
	t.Cleanup(s.Close)
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, &Policy{
		Name: clientName, Match: matchSuffix("corp.test"), Allow: (&recorder{}).allow,
	})

	resp := query(t, "udp", addr, "", "a.corp.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
	is.Equal(len(resp.Answer), 1)
}

func TestUpstreamDown(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	dead := freeAddr(t, "127.0.0.1")
	s, err := New(zaptest.NewLogger(t), Config{
		Upstreams: []string{dead.String()},
		Timeout:   300 * time.Millisecond,
	})
	is.NoErr(err)
	addr := freeAddr(t, "127.0.0.1")
	is.NoErr(s.Acquire(addr))
	t.Cleanup(s.Close)
	s.Register([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, &Policy{
		Name: clientName, Match: matchSuffix("corp.test"), Allow: (&recorder{}).allow,
	})

	resp := query(t, "udp", addr, "", "a.corp.test", dns.TypeA)
	is.Equal(resp.Rcode, dns.RcodeServerFailure)
}

func TestListenerRefcount(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, nil))
	s, err := New(zaptest.NewLogger(t), Config{Upstreams: []string{up.addr}})
	is.NoErr(err)
	addr := freeAddr(t, "127.0.0.1")

	is.NoErr(s.Acquire(addr))
	is.NoErr(s.Acquire(addr))
	s.Release(addr)

	// still listening after the first release
	c := dns.Client{Net: "tcp", Timeout: time.Second}
	m := new(dns.Msg)
	m.SetQuestion(zoneA, dns.TypeA)
	_, _, err = c.Exchange(m, addr.String())
	is.NoErr(err)

	s.Release(addr)
	_, _, err = c.Exchange(m, addr.String())
	is.True(err != nil)
}

func TestIPv6Listener(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		zoneA: {recAAAA},
	}))
	s, err := New(zaptest.NewLogger(t), Config{Upstreams: []string{up.addr}, Timeout: time.Second})
	is.NoErr(err)
	addr := freeAddr(t, "::1") // skips if the host has no IPv6
	is.NoErr(s.Acquire(addr))
	t.Cleanup(s.Close)

	rec := &recorder{}
	s.Register([]netip.Addr{netip.MustParseAddr("::1")}, &Policy{
		Name: "client6", Match: matchSuffix("corp.test"), HasIPv6: true, Allow: rec.allow,
	})
	resp := query(t, "udp", addr, "", "a.corp.test", dns.TypeAAAA)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
	is.Equal(len(resp.Answer), 1)
	is.Equal(rec.all()[0].Addr, netip.MustParseAddr("fd00::1"))
}

func TestSystemUpstreams(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	is.Equal(SystemUpstreams("/nonexistent"), []string{"1.1.1.1:53"})
}
