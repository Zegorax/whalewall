// Package dnsproxy implements a filtering DNS forwarder that decides, per
// querying container, whether a name may be resolved and tells the
// firewall which addresses the answer opened up before the answer is
// returned to the container.
package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	netUDP = "udp"
	netTCP = "tcp"
)

const (
	// the defaults of the Config fields with the same names
	defaultMinTTL  = 30 * time.Second
	defaultGrace   = 5 * time.Second
	defaultTimeout = 3 * time.Second
	defaultMaxTTL  = time.Hour
	// startTimeout is how long Acquire waits for a listener to come up
	startTimeout = 3 * time.Second
	// maxCNAMEChain is how many CNAME hops filterAnswer follows; longer
	// chains are cut so a looping or huge chain can't cost much time
	maxCNAMEChain = 16
	// maxAddrsPerAnswer limits how many addresses a single answer can
	// open, an upstream controlled by an attacker could return thousands
	maxAddrsPerAnswer = 64
)

// Resolved is an address that was returned for an allowed name. The
// firewall allows it for TTL and then forgets it.
type Resolved struct {
	Addr netip.Addr
	// TTL is the time the firewall should keep the address allowed,
	// after the configured minimum TTL and grace period were applied.
	TTL time.Duration
}

// Policy is the DNS policy of a single container. The server finds the
// policy of a query by its source address, which is why containers have to
// use the server directly and not through another resolver.
type Policy struct {
	// Name is the container name, used for logging.
	Name string
	// Match reports whether a normalized (lower-case, no trailing dot)
	// name is allowed to be resolved.
	Match func(name string) bool
	// HasIPv6 is true if the container has an IPv6 address. If it
	// doesn't AAAA queries are answered with an empty answer.
	HasIPv6 bool
	// Reject reports addresses that must never be allowed even if an
	// allowed name resolves to them, such as the host's addresses on the
	// container's networks. May be nil.
	Reject func(addr netip.Addr) bool
	// Allow is called with the queried name and the addresses of an
	// allowed answer before the answer is returned. If it returns an
	// error the query fails, so the container never gets an address
	// that the firewall doesn't allow yet.
	Allow func(ctx context.Context, name string, addrs []Resolved) error
}

// Config configures a [Server].
type Config struct {
	// Upstreams are the "host:port" addresses of upstream resolvers.
	Upstreams []string
	// MinTTL is the minimum time an address stays allowed.
	MinTTL time.Duration
	// Grace is added to the TTL of every address.
	Grace time.Duration
	// MaxTTL is the maximum time an address stays allowed, no matter how
	// large the TTL of the record is.
	MaxTTL time.Duration
	// Timeout is the timeout of a single upstream exchange.
	Timeout time.Duration
	// QueryRate is the number of queries per second a container can
	// make on average, QueryBurst how many it can make at once.
	QueryRate  float64
	QueryBurst int
	// MaxInflight is the number of queries of a container that can be
	// waiting for an upstream at the same time.
	MaxInflight int
	// MaxTCPConnsPerSource is the number of TCP connections a container
	// can hold open.
	MaxTCPConnsPerSource int
}

// Server is a DNS server that can listen on several addresses and
// distinguishes containers by their source address.
type Server struct {
	cfg    Config
	logger *zap.Logger

	// mtx guards policies, which is looked up for every query, and
	// listeners
	mtx       sync.RWMutex
	policies  map[netip.Addr]*Policy
	listeners map[netip.AddrPort]*listener

	// srcMtx guards sources, the per container state of the limits in
	// limits.go; unmanagedLog limits the log lines of unknown sources
	srcMtx       sync.Mutex
	sources      map[netip.Addr]*sourceState
	unmanagedLog globalLog

	// tcpTotal is the number of open TCP connections of all sources
	tcpMtx   sync.Mutex
	tcpTotal int
}

// listener is the UDP and TCP servers on one address. It is shared by all
// containers that use that address (one per gateway), so it is reference
// counted.
type listener struct {
	refs    int
	servers []*dns.Server
}

// New creates a Server. Zero values in cfg are replaced by the defaults.
func New(logger *zap.Logger, cfg Config) (*Server, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("no upstream DNS servers configured")
	}
	if cfg.MinTTL == 0 {
		cfg.MinTTL = defaultMinTTL
	}
	if cfg.Grace == 0 {
		cfg.Grace = defaultGrace
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = defaultMaxTTL
	}
	// a maximum below the minimum would make no sense
	cfg.MaxTTL = max(cfg.MaxTTL, cfg.MinTTL)
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.QueryRate <= 0 {
		cfg.QueryRate = defaultQueryRate
	}
	if cfg.QueryBurst <= 0 {
		cfg.QueryBurst = defaultQueryBurst
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = defaultMaxInflight
	}
	if cfg.MaxTCPConnsPerSource <= 0 {
		cfg.MaxTCPConnsPerSource = defaultMaxTCPConnsPerSource
	}

	return &Server{
		cfg:       cfg,
		logger:    logger.Named("dns"),
		policies:  make(map[netip.Addr]*Policy),
		listeners: make(map[netip.AddrPort]*listener),
		sources:   make(map[netip.Addr]*sourceState),
	}, nil
}

// SystemUpstreams returns the nameservers in resolvConf, or a public
// resolver if none were found.
func SystemUpstreams(resolvConf string) []string {
	cc, err := dns.ClientConfigFromFile(resolvConf)
	if err != nil || len(cc.Servers) == 0 {
		return []string{"1.1.1.1:53"}
	}
	upstreams := make([]string, 0, len(cc.Servers))
	for _, s := range cc.Servers {
		upstreams = append(upstreams, net.JoinHostPort(s, cc.Port))
	}

	return upstreams
}

// Register sets the policy for queries originating from addrs. Addresses
// are stored unmapped so an IPv4-mapped IPv6 source finds its IPv4 policy.
func (s *Server) Register(addrs []netip.Addr, p *Policy) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for _, a := range addrs {
		s.policies[a.Unmap()] = p
	}
}

// Unregister removes policy p from addrs. Queries from them are refused
// afterwards. Addresses that another policy was registered for in the
// meantime, which happens when a container's address is reused before the
// previous container was cleaned up, are left alone.
func (s *Server) Unregister(addrs []netip.Addr, p *Policy) {
	if p == nil {
		return
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()
	var removed []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if s.policies[a] == p {
			delete(s.policies, a)
			removed = append(removed, a)
		}
	}
	s.forgetSources(removed)
}

// policy returns the policy of a source address, if it has one.
func (s *Server) policy(a netip.Addr) (*Policy, bool) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	p, ok := s.policies[a.Unmap()]
	return p, ok
}

// Acquire makes the server listen on addr (UDP and TCP). Every call
// must be paired with a call to Release; the sockets are closed when
// the last reference is released.
func (s *Server) Acquire(addr netip.AddrPort) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if l, ok := s.listeners[addr]; ok {
		l.refs++
		return nil
	}

	l := &listener{refs: 1}
	for _, network := range []string{netUDP, netTCP} {
		srv, err := s.startServer(addr, network)
		if err != nil {
			for _, started := range l.servers {
				_ = started.Shutdown()
			}
			return fmt.Errorf("error listening on %s/%s: %w", addr, network, err)
		}
		l.servers = append(l.servers, srv)
	}
	s.listeners[addr] = l
	s.logger.Info("listening", zap.Stringer("addr", addr))

	return nil
}

// startServer starts a DNS server for one network and returns once it is
// accepting queries. TCP servers get a limitedListener so unknown sources
// and connection floods are dealt with before any DNS is parsed.
func (s *Server) startServer(addr netip.AddrPort, network string) (*dns.Server, error) {
	started := make(chan struct{})
	srv := &dns.Server{
		Addr:              addr.String(),
		Net:               network,
		Handler:           s,
		NotifyStartedFunc: func() { close(started) },
		ReadTimeout:       s.cfg.Timeout,
		WriteTimeout:      s.cfg.Timeout,
	}
	if network == netTCP {
		ln, err := net.Listen(netTCP, addr.String())
		if err != nil {
			return nil, err
		}
		srv.Listener = &limitedListener{Listener: ln, s: s}
	}
	errCh := make(chan error, 1)
	go func() {
		// ListenAndServe ignores srv.Listener, so a server with our own
		// listener has to be started with ActivateAndServe
		if srv.Listener != nil {
			errCh <- srv.ActivateAndServe()
			return
		}
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-started:
		return srv, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(startTimeout):
		_ = srv.Shutdown()
		return nil, errors.New("timed out starting DNS server")
	}
}

// Release drops a reference taken by Acquire.
func (s *Server) Release(addr netip.AddrPort) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	l, ok := s.listeners[addr]
	if !ok {
		return
	}
	l.refs--
	if l.refs > 0 {
		return
	}
	for _, srv := range l.servers {
		_ = srv.Shutdown()
	}
	delete(s.listeners, addr)
	s.logger.Info("stopped listening", zap.Stringer("addr", addr))
}

// Close stops all listeners.
func (s *Server) Close() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	for addr, l := range s.listeners {
		for _, srv := range l.servers {
			_ = srv.Shutdown()
		}
		delete(s.listeners, addr)
	}
}

// ServeDNS implements [dns.Handler].
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := s.handle(w, req)
	if resp == nil {
		// the query was dropped on purpose, nothing is sent
		return
	}
	// UDP answers are cut to the size the client said it can take (512
	// bytes without EDNS0), the client retries over TCP if it is truncated
	if w.RemoteAddr().Network() == netUDP {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		resp.Truncate(size)
	}
	if err := w.WriteMsg(resp); err != nil {
		s.logger.Debug("error writing response", zap.Error(err))
	}
}

// remoteAddr returns the unmapped source address of a query.
func remoteAddr(w dns.ResponseWriter) (netip.Addr, bool) {
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		return ip.Unmap(), ok
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		return ip.Unmap(), ok
	}

	return netip.Addr{}, false
}

// handle answers a query, or returns nil to drop it. In order it:
//
//  1. refuses sources without a policy (default deny)
//  2. applies the rate limits of the source
//  3. refuses anything but a plain query for one name
//  4. answers NXDOMAIN for names the policy doesn't allow, without asking
//     the upstream, so a denied name never leaves the host
//  5. forwards allowed names, removes unsafe records from the answer and
//     lets the firewall allow the addresses before returning it
func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) *dns.Msg {
	src, ok := remoteAddr(w)
	if !ok {
		return reply(req, dns.RcodeRefused)
	}
	p, ok := s.policy(src)
	if !ok {
		// unknown sources are default-deny
		if s.logOK(src) {
			s.logger.Warn("refusing query from unmanaged source", zap.Stringer("source", src))
		}
		return reply(req, dns.RcodeRefused)
	}
	release, ok := s.admit(src)
	if !ok {
		// over the limits; UDP queries are dropped, a client that waits
		// for a TCP answer gets one
		if s.logOK(src) {
			s.logger.Warn("rate limiting DNS queries", zap.String("container.name", p.Name))
		}
		if w.RemoteAddr().Network() == netUDP {
			return nil
		}
		return reply(req, dns.RcodeRefused)
	}
	defer release()
	if req.Opcode != dns.OpcodeQuery {
		return reply(req, dns.RcodeNotImplemented)
	}
	if len(req.Question) != 1 {
		return reply(req, dns.RcodeFormatError)
	}

	q := req.Question[0]
	name := asciiLower(strings.TrimSuffix(q.Name, "."))
	logger := s.logger.With(
		zap.String("container.name", p.Name),
		zap.String("dns.name", name),
		zap.String("dns.type", dns.TypeToString[q.Qtype]),
	)

	// only plain internet class lookups of single records are allowed;
	// zone transfers and ANY queries would reveal more than the names a
	// container is allowed to resolve
	if q.Qclass != dns.ClassINET || q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR || q.Qtype == dns.TypeANY {
		if s.logOK(src) {
			logger.Warn("refusing unsupported DNS query", zap.String("dns.class", dns.ClassToString[q.Qclass]))
		}
		return reply(req, dns.RcodeRefused)
	}
	// names are matched as ASCII, anything else (the library escapes
	// non-printable bytes and dots inside labels with a backslash) is not
	// a name that could have been allowed
	if strings.ContainsRune(name, '\\') {
		if s.logOK(src) {
			logger.Warn("denied DNS query with escaped characters")
		}
		return reply(req, dns.RcodeNameError)
	}

	if !p.Match(name) {
		if s.logOK(src) {
			logger.Warn("denied DNS query")
		}
		return reply(req, dns.RcodeNameError)
	}
	// a container without an IPv6 address can't use AAAA records; an empty
	// answer makes it fall back to IPv4 at once and not wait for a timeout
	if q.Qtype == dns.TypeAAAA && !p.HasIPv6 {
		return reply(req, dns.RcodeSuccess)
	}

	// room for a UDP exchange and a TCP retry of one upstream
	ctx, cancel := context.WithTimeout(context.Background(), 2*s.cfg.Timeout+s.cfg.Grace)
	defer cancel()

	upstreamResp, err := s.forward(ctx, req)
	if err != nil {
		logger.Error("error forwarding DNS query", zap.Error(err))
		return reply(req, dns.RcodeServerFailure)
	}
	// forward used its own ID, the container expects the one it sent
	upstreamResp.Id = req.Id
	if upstreamResp.Rcode != dns.RcodeSuccess {
		// NXDOMAIN and the like open nothing, pass them on as they are
		return upstreamResp
	}

	// filterAnswer also edits upstreamResp in place, so what is returned
	// below contains exactly the addresses that are allowed here
	resolved := s.filterAnswer(upstreamResp, q.Name, p.Reject)
	if len(resolved) != 0 {
		if err := p.Allow(ctx, name, resolved); err != nil {
			logger.Error("error allowing addresses", zap.Error(err))
			return reply(req, dns.RcodeServerFailure)
		}
		logger.Debug("allowed DNS query", zap.Int("addresses", len(resolved)))
	}

	return upstreamResp
}

// reply returns an answer to req that only has a response code.
func reply(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	resp.RecursionAvailable = true

	return resp
}

// forward sends req to the upstream resolvers, returning the first
// usable response. A query goes out over UDP and is repeated over TCP if the
// answer was truncated. SERVFAIL and REFUSED mean the upstream can't help,
// so the next one is tried; NXDOMAIN is a real answer and is returned.
func (s *Server) forward(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var errs []error
	for _, upstream := range s.cfg.Upstreams {
		upReq := req.Copy()
		upReq.Id = dns.Id()

		resp, err := s.exchange(ctx, netUDP, upstream, upReq)
		if err == nil && resp.Truncated {
			resp, err = s.exchange(ctx, netTCP, upstream, upReq)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", upstream, err))
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			errs = append(errs, fmt.Errorf("%s: %s", upstream, dns.RcodeToString[resp.Rcode]))
			continue
		}

		return resp, nil
	}

	return nil, errors.Join(errs...)
}

// exchange sends one query to one upstream. The question in the response
// has to be the one that was asked, so an upstream (or an attacker who can
// answer in its place) can't use the query of an allowed name to deliver
// the answer to another one.
func (s *Server) exchange(ctx context.Context, network, upstream string, req *dns.Msg) (*dns.Msg, error) {
	c := dns.Client{Net: network, Timeout: s.cfg.Timeout}
	resp, _, err := c.ExchangeContext(ctx, req, upstream)
	if err != nil {
		return nil, err
	}
	if len(resp.Question) != 1 || !strings.EqualFold(resp.Question[0].Name, req.Question[0].Name) {
		return nil, errors.New("upstream answered a different question")
	}

	return resp, nil
}

// filterAnswer returns the addresses that are reachable from qname by
// following CNAME records. Records that are not part of that chain are
// removed from the answer and so are addresses that must never be
// reachable through DNS (loopback, link-local, ...), preventing a
// permitted name from pointing a container at the host.
//
// The TTL of each address is the record's TTL, raised to MinTTL and cut
// to MaxTTL, plus Grace, so a huge TTL can't keep an address open for long
// and a zero TTL doesn't close it before the connection is made. At most
// maxAddrsPerAnswer addresses are returned.
func (s *Server) filterAnswer(resp *dns.Msg, qname string, reject func(netip.Addr) bool) []Resolved {
	// owners are the names that belong to this answer: the queried name
	// and every CNAME target reachable from it
	owners := map[string]bool{strings.ToLower(qname): true}
	// follow CNAMEs; the answer is usually ordered but don't rely on it
	for range maxCNAMEChain {
		grew := false
		for _, rr := range resp.Answer {
			cname, ok := rr.(*dns.CNAME)
			if !ok || !owners[strings.ToLower(cname.Hdr.Name)] {
				continue
			}
			target := strings.ToLower(cname.Target)
			if !owners[target] {
				owners[target] = true
				grew = true
			}
		}
		if !grew {
			break
		}
	}

	var (
		resolved = make([]Resolved, 0, len(resp.Answer))
		answer   = make([]dns.RR, 0, len(resp.Answer))
	)
	for _, rr := range resp.Answer {
		if !owners[strings.ToLower(rr.Header().Name)] {
			continue
		}

		var ip net.IP
		switch rr := rr.(type) {
		case *dns.A:
			ip = rr.A
		case *dns.AAAA:
			ip = rr.AAAA
		default:
			// CNAMEs and other records carry no address, keep them
			answer = append(answer, rr)
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		// ::ffff:127.0.0.1 is loopback too
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || (reject != nil && reject(addr)) {
			s.logger.Warn("dropping unsafe address from DNS answer", zap.Stringer("addr", addr), zap.String("dns.name", qname))
			continue
		}
		if len(resolved) >= maxAddrsPerAnswer {
			s.logger.Warn("dropping addresses over the limit from DNS answer", zap.String("dns.name", qname))
			continue
		}

		answer = append(answer, rr)
		ttl := time.Duration(rr.Header().Ttl) * time.Second
		ttl = min(max(ttl, s.cfg.MinTTL), s.cfg.MaxTTL)
		resolved = append(resolved, Resolved{Addr: addr, TTL: ttl + s.cfg.Grace})
	}
	resp.Answer = answer
	// additional records may carry unrelated addresses
	resp.Extra = filterExtra(resp.Extra)

	return resolved
}

// filterExtra keeps only the OPT pseudo-record (EDNS0), so the additional
// section can't smuggle in glue records with addresses nobody checked.
func filterExtra(extra []dns.RR) []dns.RR {
	kept := extra[:0]
	for _, rr := range extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			kept = append(kept, rr)
		}
	}

	return kept
}

// asciiLower lower-cases ASCII letters only; see the matcher in the
// whalewall package for why strings.ToLower is not used.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
