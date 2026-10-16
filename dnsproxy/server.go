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
	defaultMinTTL  = 30 * time.Second
	defaultGrace   = 5 * time.Second
	defaultTimeout = 3 * time.Second
	startTimeout   = 3 * time.Second
	maxCNAMEChain  = 16
)

// Resolved is an address that was returned for an allowed name.
type Resolved struct {
	Addr netip.Addr
	// TTL is the time the firewall should keep the address allowed,
	// after the configured minimum TTL and grace period were applied.
	TTL time.Duration
}

// Policy is the DNS policy of a single container.
type Policy struct {
	// Name is the container name, used for logging.
	Name string
	// Match reports whether a normalized (lower-case, no trailing dot)
	// name is allowed to be resolved.
	Match func(name string) bool
	// HasIPv6 is true if the container has an IPv6 address. If it
	// doesn't AAAA queries are answered with an empty answer.
	HasIPv6 bool
	// Allow is called with the queried name and the addresses of an allowed answer before
	// the answer is returned. If it returns an error the query fails.
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
	// Timeout is the timeout of a single upstream exchange.
	Timeout time.Duration
}

// Server is a DNS server that can listen on several addresses and
// distinguishes containers by their source address.
type Server struct {
	cfg    Config
	logger *zap.Logger

	mtx       sync.RWMutex
	policies  map[netip.Addr]*Policy
	listeners map[netip.AddrPort]*listener
}

type listener struct {
	refs    int
	servers []*dns.Server
}

// New creates a Server.
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
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}

	return &Server{
		cfg:       cfg,
		logger:    logger.Named("dns"),
		policies:  make(map[netip.Addr]*Policy),
		listeners: make(map[netip.AddrPort]*listener),
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

// Register sets the policy for queries originating from addrs.
func (s *Server) Register(addrs []netip.Addr, p *Policy) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for _, a := range addrs {
		s.policies[a.Unmap()] = p
	}
}

// Unregister removes the policy of addrs. Queries from them are refused
// afterwards.
func (s *Server) Unregister(addrs []netip.Addr) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for _, a := range addrs {
		delete(s.policies, a.Unmap())
	}
}

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
	for _, network := range []string{"udp", "tcp"} {
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
	errCh := make(chan error, 1)
	go func() {
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
		return
	}
	if w.RemoteAddr().Network() == "udp" {
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

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) *dns.Msg {
	src, ok := remoteAddr(w)
	if !ok {
		return reply(req, dns.RcodeRefused)
	}
	p, ok := s.policy(src)
	if !ok {
		// unknown sources are default-deny
		s.logger.Warn("refusing query from unmanaged source", zap.Stringer("source", src))
		return reply(req, dns.RcodeRefused)
	}
	if req.Opcode != dns.OpcodeQuery {
		return reply(req, dns.RcodeNotImplemented)
	}
	if len(req.Question) != 1 {
		return reply(req, dns.RcodeFormatError)
	}

	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	logger := s.logger.With(
		zap.String("container.name", p.Name),
		zap.String("dns.name", name),
		zap.String("dns.type", dns.TypeToString[q.Qtype]),
	)

	if !p.Match(name) {
		logger.Warn("denied DNS query")
		return reply(req, dns.RcodeNameError)
	}
	if q.Qtype == dns.TypeAAAA && !p.HasIPv6 {
		return reply(req, dns.RcodeSuccess)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*s.cfg.Timeout+s.cfg.Grace)
	defer cancel()

	upstreamResp, err := s.forward(ctx, req)
	if err != nil {
		logger.Error("error forwarding DNS query", zap.Error(err))
		return reply(req, dns.RcodeServerFailure)
	}
	upstreamResp.Id = req.Id
	if upstreamResp.Rcode != dns.RcodeSuccess {
		return upstreamResp
	}

	resolved := s.filterAnswer(upstreamResp, q.Name)
	if len(resolved) != 0 {
		if err := p.Allow(ctx, name, resolved); err != nil {
			logger.Error("error allowing addresses", zap.Error(err))
			return reply(req, dns.RcodeServerFailure)
		}
		logger.Debug("allowed DNS query", zap.Int("addresses", len(resolved)))
	}

	return upstreamResp
}

func reply(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	resp.RecursionAvailable = true

	return resp
}

// forward sends req to the upstream resolvers, returning the first
// usable response.
func (s *Server) forward(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var errs []error
	for _, upstream := range s.cfg.Upstreams {
		upReq := req.Copy()
		upReq.Id = dns.Id()

		resp, err := s.exchange(ctx, "udp", upstream, upReq)
		if err == nil && resp.Truncated {
			resp, err = s.exchange(ctx, "tcp", upstream, upReq)
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
func (s *Server) filterAnswer(resp *dns.Msg, qname string) []Resolved {
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
			answer = append(answer, rr)
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			s.logger.Warn("dropping unsafe address from DNS answer", zap.Stringer("addr", addr), zap.String("dns.name", qname))
			continue
		}

		answer = append(answer, rr)
		ttl := time.Duration(rr.Header().Ttl) * time.Second
		resolved = append(resolved, Resolved{Addr: addr, TTL: max(ttl, s.cfg.MinTTL) + s.cfg.Grace})
	}
	resp.Answer = answer
	// additional records may carry unrelated addresses
	resp.Extra = filterExtra(resp.Extra)

	return resolved
}

// filterExtra keeps only the OPT pseudo-record.
func filterExtra(extra []dns.RR) []dns.RR {
	kept := extra[:0]
	for _, rr := range extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			kept = append(kept, rr)
		}
	}

	return kept
}
