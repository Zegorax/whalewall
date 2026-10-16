package dnsproxy

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/miekg/dns"
)

const (
	srcLoopback = "127.0.0.1"
	policyZone  = "corp.test"
)

// register adds a policy for the loopback source address used by tests.
func registerLoopback(s *Server, p *Policy) {
	s.Register([]netip.Addr{netip.MustParseAddr(srcLoopback)}, p)
}

func rawQuery(t *testing.T, network string, srv netip.AddrPort, m *dns.Msg) *dns.Msg {
	t.Helper()
	c := dns.Client{Net: network, Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(m, srv.String())
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return resp
}

func TestUnsupportedQueriesRefused(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: {recA}}))
	s, addr := newServer(t, up, time.Second)
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: (&recorder{}).allow})

	tests := []struct {
		name   string
		qtype  uint16
		qclass uint16
	}{
		{"AXFR", dns.TypeAXFR, dns.ClassINET},
		{"IXFR", dns.TypeIXFR, dns.ClassINET},
		{"ANY", dns.TypeANY, dns.ClassINET},
		{"CHAOS TXT", dns.TypeTXT, dns.ClassCHAOS},
		{"HESIOD A", dns.TypeA, dns.ClassHESIOD},
		{"class ANY", dns.TypeA, dns.ClassANY},
	}
	for _, tt := range tests {
		m := new(dns.Msg)
		m.Question = []dns.Question{{Name: zoneA, Qtype: tt.qtype, Qclass: tt.qclass}}
		m.Id = dns.Id()
		resp := rawQuery(t, "udp", addr, m)
		is.Equal(resp.Rcode, dns.RcodeRefused) // tt.name
	}
	is.Equal(up.queries.Load(), int32(0)) // nothing was forwarded
}

func TestMalformedQuestions(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: {recA}}))
	s, addr := newServer(t, up, time.Second)
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: (&recorder{}).allow})

	// no question
	m := new(dns.Msg)
	m.Id = dns.Id()
	is.Equal(rawQuery(t, "udp", addr, m).Rcode, dns.RcodeFormatError)

	// two questions, the second one denied; must not be a way to ask for
	// names that aren't allowed
	m = new(dns.Msg)
	m.Id = dns.Id()
	m.Question = []dns.Question{
		{Name: zoneA, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "evil.other.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	is.Equal(rawQuery(t, "udp", addr, m).Rcode, dns.RcodeFormatError)

	// other opcodes
	for _, op := range []int{dns.OpcodeIQuery, dns.OpcodeStatus, dns.OpcodeNotify, dns.OpcodeUpdate} {
		m = new(dns.Msg)
		m.Id = dns.Id()
		m.Opcode = op
		m.Question = []dns.Question{{Name: zoneA, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		resp := rawQuery(t, "udp", addr, m)
		is.Equal(resp.Rcode, dns.RcodeNotImplemented) // opcode op
	}
	is.Equal(up.queries.Load(), int32(0))
}

func TestNamesThatOnlyLookAllowed(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{"kube.corp.test.": {"kube.corp.test. 60 IN A 10.0.0.1"}}))
	s, addr := newServer(t, up, time.Second)
	// only the exact name is allowed
	registerLoopback(s, &Policy{
		Name:  clientName,
		Match: func(name string) bool { return name == "kube.corp.test" },
		Allow: (&recorder{}).allow,
	})

	// sanity check: the real name works, in any case
	for _, name := range []string{"kube.corp.test.", "KUBE.Corp.TEST."} {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		is.Equal(rawQuery(t, "udp", addr, m).Rcode, dns.RcodeSuccess)
	}
	forwarded := up.queries.Load()

	lookalikes := []string{
		"Kube.corp.test.",      // Kelvin sign folds to "k" with Unicode lower-casing
		"kubė.corp.test.",     // combining dot above
		"kıbe.corp.test.",      // dotless i
		"kube.corp.test\x00.",  // NUL in the last label
		"kube\\.corp.test.",    // dot inside the first label
		"kube.corp\\.test.",    // dot inside the second label
		"kube\\000.corp.test.", // escaped NUL
		"kube.corp.test.evil.net.",
		"xkube.corp.test.",
	}
	for _, name := range lookalikes {
		m := new(dns.Msg)
		m.Id = dns.Id()
		m.Question = []dns.Question{{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		resp, _, err := (&dns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(m, addr.String())
		if err != nil {
			// a name the library refuses to pack can't be sent at all
			continue
		}
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("look-alike %q got rcode %s with %d answers", name, dns.RcodeToString[resp.Rcode], len(resp.Answer))
		}
		is.Equal(len(resp.Answer), 0)
	}
	is.Equal(up.queries.Load(), forwarded) // no look-alike reached the upstream
}

func TestGarbagePackets(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: {recA}}))
	s, addr := newServer(t, up, time.Second)
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: (&recorder{}).allow})

	garbage := [][]byte{
		{},
		{0},
		{0, 1, 2},
		make([]byte, 11), // shorter than a header
		make([]byte, 12), // header only
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		// header claiming 65535 questions
		{0, 1, 1, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c},
		// compression pointer loop
		{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1},
		// label length beyond the packet
		{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x3f, 'a', 'b'},
	}
	for i := 0; i < 50; i++ {
		b := make([]byte, 1+i*7)
		_, _ = rand.Read(b)
		garbage = append(garbage, b)
	}

	conn, err := net.Dial("udp", addr.String())
	is.NoErr(err)
	defer conn.Close()
	for _, g := range garbage {
		_, _ = conn.Write(g)
	}

	// over TCP: bad length prefixes and truncated messages
	for _, g := range garbage {
		tc, err := net.Dial("tcp", addr.String())
		is.NoErr(err)
		_, _ = tc.Write(append([]byte{byte(len(g) >> 8), byte(len(g))}, g...))
		_ = tc.Close()
	}
	tc, err := net.Dial("tcp", addr.String())
	is.NoErr(err)
	_, _ = tc.Write([]byte{0xff, 0xff, 1, 2, 3})
	_ = tc.Close()

	// the server is still alive and answering
	m := new(dns.Msg)
	m.SetQuestion(zoneA, dns.TypeA)
	is.Equal(rawQuery(t, "udp", addr, m).Rcode, dns.RcodeSuccess)
	is.Equal(rawQuery(t, "tcp", addr, m).Rcode, dns.RcodeSuccess)
}

func TestTTLIsCapped(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		zoneA: {zoneA + " 4294967295 IN A 10.0.0.1", zoneA + " 1 IN A 10.0.0.2"},
	}))
	s, err := New(testLogger(t), Config{
		Upstreams: []string{up.addr},
		MinTTL:    10 * time.Second,
		MaxTTL:    time.Minute,
		Grace:     time.Second,
		Timeout:   time.Second,
	})
	is.NoErr(err)
	addr := acquireFree(t, s, srcLoopback)
	t.Cleanup(s.Close)

	rec := &recorder{}
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: rec.allow})

	m := new(dns.Msg)
	m.SetQuestion(zoneA, dns.TypeA)
	is.Equal(rawQuery(t, "udp", addr, m).Rcode, dns.RcodeSuccess)

	got := map[netip.Addr]time.Duration{}
	for _, r := range rec.all() {
		got[r.Addr] = r.TTL
	}
	is.Equal(got[netip.MustParseAddr("10.0.0.1")], time.Minute+time.Second)    // an attacker's huge TTL is capped
	is.Equal(got[netip.MustParseAddr("10.0.0.2")], 10*time.Second+time.Second) // a tiny TTL is raised to the minimum
}

func TestAddressCountIsCapped(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	var rrs []string
	for i := 0; i < 300; i++ {
		rrs = append(rrs, fmt.Sprintf("%s 60 IN A 10.9.%d.%d", zoneA, i/250, i%250+1))
	}
	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: rrs}))
	s, addr := newServer(t, up, time.Second)

	rec := &recorder{}
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: rec.allow})

	m := new(dns.Msg)
	m.SetQuestion(zoneA, dns.TypeA)
	resp := rawQuery(t, "tcp", addr, m)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
	// the container never sees addresses that were not allowed
	is.Equal(len(resp.Answer), maxAddrsPerAnswer)
	is.Equal(len(rec.all()), maxAddrsPerAnswer)
}

func TestRejectedAddresses(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	host := netip.MustParseAddr("172.18.0.1")
	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{
		zoneA: {
			zoneA + " 60 IN A 172.18.0.1",
			zoneA + " 60 IN A 10.0.0.1",
			zoneA + " 60 IN A 127.0.0.1",
			zoneA + " 60 IN A 169.254.169.254",
			zoneA + " 60 IN A 224.0.0.1",
			zoneA + " 60 IN A 0.0.0.0",
		},
	}))
	s, addr := newServer(t, up, time.Second)

	rec := &recorder{}
	registerLoopback(s, &Policy{
		Name:   clientName,
		Match:  matchSuffix(policyZone),
		Allow:  rec.allow,
		Reject: func(a netip.Addr) bool { return a == host },
	})

	m := new(dns.Msg)
	m.SetQuestion(zoneA, dns.TypeA)
	resp := rawQuery(t, "udp", addr, m)
	is.Equal(len(resp.Answer), 1)
	all := rec.all()
	is.Equal(len(all), 1)
	is.Equal(all[0].Addr, netip.MustParseAddr("10.0.0.1"))
}

func TestMismatchedUpstreamAnswers(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	// an upstream (or an attacker racing it) answering a different question
	up := newFakeUpstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Question = []dns.Question{{Name: "evil.other.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		resp.Answer = []dns.RR{rr(t, "evil.other.test. 60 IN A 10.6.6.6")}
		_ = w.WriteMsg(resp)
	})
	s, addr := newServer(t, up, time.Second)
	rec := &recorder{}
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: rec.allow})

	m := new(dns.Msg)
	m.SetQuestion(zoneA, dns.TypeA)
	resp := rawQuery(t, "udp", addr, m)
	is.Equal(resp.Rcode, dns.RcodeServerFailure)
	is.Equal(len(resp.Answer), 0)
	is.Equal(len(rec.all()), 0) // nothing was allowed
}

func TestAnswerOwnerCaseInsensitive(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	// 0x20 style case randomisation in the answer must not drop records
	up := newFakeUpstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{rr(t, "A.CoRp.TeSt. 60 IN A 10.0.0.1")}
		_ = w.WriteMsg(resp)
	})
	s, addr := newServer(t, up, time.Second)
	rec := &recorder{}
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: rec.allow})

	m := new(dns.Msg)
	m.SetQuestion(zoneA, dns.TypeA)
	resp := rawQuery(t, "udp", addr, m)
	is.Equal(resp.Rcode, dns.RcodeSuccess)
	is.Equal(len(resp.Answer), 1)
	is.Equal(len(rec.all()), 1)
}

func TestAuthorityAndAdditionalAreNotTrusted(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{rr(t, zoneA+" 60 IN A 10.0.0.1")}
		resp.Ns = []dns.RR{rr(t, "corp.test. 60 IN NS ns.evil.test.")}
		resp.Extra = []dns.RR{rr(t, "ns.evil.test. 60 IN A 10.6.6.6"), rr(t, "ns.evil.test. 60 IN AAAA fd00::6")}
		_ = w.WriteMsg(resp)
	})
	s, addr := newServer(t, up, time.Second)
	rec := &recorder{}
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), HasIPv6: true, Allow: rec.allow})

	m := new(dns.Msg)
	m.SetQuestion(zoneA, dns.TypeA)
	resp := rawQuery(t, "udp", addr, m)
	is.Equal(len(rec.all()), 1)
	is.Equal(len(resp.Extra), 0)
	// glue for a name the container is not allowed to resolve was removed
	for _, r := range resp.Extra {
		is.True(r.Header().Rrtype == dns.TypeOPT)
	}
}

func TestConcurrentQueries(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: {recA}}))
	s, addr := newServer(t, up, time.Second)
	rec := &recorder{}
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: rec.allow})

	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			network := "udp"
			name := zoneA
			want := dns.RcodeSuccess
			if i%4 == 0 {
				network = "tcp"
			}
			if i%5 == 0 {
				name = "denied.other.test."
				want = dns.RcodeNameError
			}
			m := new(dns.Msg)
			m.SetQuestion(name, dns.TypeA)
			c := dns.Client{Net: network, Timeout: 2 * time.Second}
			resp, _, err := c.Exchange(m, addr.String())
			// UDP is lossy when many packets hit a loaded host at once;
			// a client would retry
			for try := 0; err != nil && network == "udp" && try < 3; try++ {
				resp, _, err = c.Exchange(m, addr.String())
			}
			if err != nil {
				errs <- err
				return
			}
			if resp.Rcode != want {
				errs <- fmt.Errorf("%s: rcode %d, wanted %d", name, resp.Rcode, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		is.NoErr(err)
	}
}

func TestSlowTCPClientDoesNotBlockOthers(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: {recA}}))
	s, addr := newServer(t, up, time.Second)
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: (&recorder{}).allow})

	// connections that send half a message and then nothing
	var slow []net.Conn
	for i := 0; i < 50; i++ {
		c, err := net.Dial("tcp", addr.String())
		is.NoErr(err)
		_, _ = c.Write([]byte{0, 40, 1})
		slow = append(slow, c)
	}
	defer func() {
		for _, c := range slow {
			_ = c.Close()
		}
	}()

	m := new(dns.Msg)
	m.SetQuestion(zoneA, dns.TypeA)
	start := time.Now()
	is.Equal(rawQuery(t, "tcp", addr, m).Rcode, dns.RcodeSuccess)
	is.True(time.Since(start) < time.Second)
}

func TestLargeAnswerIsTruncatedOverUDP(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	var rrs []string
	for i := 0; i < 60; i++ {
		rrs = append(rrs, fmt.Sprintf("%s 60 IN A 10.9.0.%d", zoneA, i+1))
	}
	up := newFakeUpstream(t, zoneHandler(t, map[string][]string{zoneA: rrs}))
	s, addr := newServer(t, up, time.Second)
	registerLoopback(s, &Policy{Name: clientName, Match: matchSuffix(policyZone), Allow: (&recorder{}).allow})

	m := new(dns.Msg)
	m.SetQuestion(zoneA, dns.TypeA)
	resp := rawQuery(t, "udp", addr, m)
	is.True(resp.Truncated)        // the client is told to retry over TCP
	is.True(len(resp.Answer) < 60) // and carries only what fits
	is.Equal(len(rawQuery(t, "tcp", addr, m).Answer), 60)
}
