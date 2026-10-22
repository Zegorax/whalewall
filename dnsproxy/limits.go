package dnsproxy

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"
)

// The limits in this file keep one container from using up the resolver
// for the others: a container that floods it with queries or holds
// connections open only exhausts its own share. The defaults are far above
// what a normal workload needs; Config can override them.
const (
	// defaultQueryRate is the sustained queries per second a container may
	// send and defaultQueryBurst how many it may send at once, see admit
	defaultQueryRate  = 100.0
	defaultQueryBurst = 200
	// defaultMaxInflight is how many queries of one container can wait
	// for the upstream at the same time
	defaultMaxInflight = 32
	// defaultMaxTCPConnsPerSource is how many TCP connections one
	// container can hold open
	defaultMaxTCPConnsPerSource = 16
	// maxTCPConns is the number of TCP connections all sources together
	// can hold open; whalewall needs file descriptors for other things
	maxTCPConns = 512
	// logBurst and logEvery limit the log lines a single source can cause
	logBurst = 5
	logEvery = time.Second
)

// sourceState is the resource use of one container. It only exists for
// sources that have a policy, so a flood from spoofed addresses can't
// make the server keep state for each of them.
type sourceState struct {
	mtx sync.Mutex
	// tokens and last are a token bucket: it refills at QueryRate per
	// second up to QueryBurst, and every admitted query takes one token
	tokens float64
	last   time.Time
	// inflight is the number of admitted queries that are not done yet
	inflight int
	// tcpConns is the number of open TCP connections
	tcpConns int
	// logTok and logLast are a second token bucket that limits log lines
	// caused by this source, see logOK
	logTok  float64
	logLast time.Time
}

// source returns the state of addr, creating it if needed.
func (s *Server) source(addr netip.Addr) *sourceState {
	s.srcMtx.Lock()
	defer s.srcMtx.Unlock()

	st, ok := s.sources[addr]
	if !ok {
		now := time.Now()
		st = &sourceState{tokens: float64(s.cfg.QueryBurst), last: now, logTok: logBurst, logLast: now}
		s.sources[addr] = st
	}

	return st
}

// forgetSources drops the state of addresses that no longer have a policy,
// for example when their container was removed.
func (s *Server) forgetSources(addrs []netip.Addr) {
	s.srcMtx.Lock()
	defer s.srcMtx.Unlock()
	for _, a := range addrs {
		delete(s.sources, a.Unmap())
	}
}

// admit decides whether a query of src is processed. The returned
// function must be called when the query is done.
//
// A query is refused when the source has used up its tokens (it sends
// faster than QueryRate once its burst is gone) or already has
// MaxInflight queries waiting for the upstream. handle drops refused UDP
// queries without an answer and answers refused TCP queries with REFUSED,
// so a flood costs the resolver almost nothing.
func (s *Server) admit(src netip.Addr) (release func(), ok bool) {
	st := s.source(src)

	st.mtx.Lock()
	defer st.mtx.Unlock()

	// refill the bucket for the time since the last query
	now := time.Now()
	st.tokens = min(float64(s.cfg.QueryBurst), st.tokens+now.Sub(st.last).Seconds()*s.cfg.QueryRate)
	st.last = now
	if st.tokens < 1 || st.inflight >= s.cfg.MaxInflight {
		return nil, false
	}
	st.tokens--
	st.inflight++

	return func() {
		st.mtx.Lock()
		st.inflight--
		st.mtx.Unlock()
	}, true
}

// logOK reports whether another line may be logged for src. Every line
// the resolver logs about a misbehaving source goes through here, so a
// flood can't be turned into a flood of log lines: a source gets a burst of
// logBurst lines and then one per logEvery.
func (s *Server) logOK(src netip.Addr) bool {
	s.srcMtx.Lock()
	st, ok := s.sources[src]
	s.srcMtx.Unlock()
	if !ok {
		// no state for this source because it has no policy, so share one
		// slow limit between all of them
		return s.unmanagedLog.allow()
	}

	st.mtx.Lock()
	defer st.mtx.Unlock()
	now := time.Now()
	st.logTok = min(logBurst, st.logTok+now.Sub(st.logLast).Seconds()/logEvery.Seconds())
	st.logLast = now
	if st.logTok < 1 {
		return false
	}
	st.logTok--

	return true
}

// globalLog limits the log lines caused by sources that have no policy. It
// allows one line per 10 seconds in total, as there is no per source state
// to count against.
type globalLog struct {
	mtx  sync.Mutex
	last time.Time
}

func (g *globalLog) allow() bool {
	g.mtx.Lock()
	defer g.mtx.Unlock()
	if time.Since(g.last) < 10*time.Second {
		return false
	}
	g.last = time.Now()

	return true
}

// acquireTCP reserves a connection slot for src. Two limits apply: a
// total of maxTCPConns for all sources, so the resolver can't use up
// whalewall's file descriptors, and MaxTCPConnsPerSource for each source,
// so one container can't take all of the total. Connections of sources
// without a policy are never accepted. A slot that was reserved must be
// given back with releaseTCP.
func (s *Server) acquireTCP(src netip.Addr) bool {
	if _, ok := s.policy(src); !ok {
		return false
	}
	st := s.source(src)

	// take a slot of the total first, then one of the source; if the source
	// is over its limit the total slot is given back
	s.tcpMtx.Lock()
	if s.tcpTotal >= maxTCPConns {
		s.tcpMtx.Unlock()
		return false
	}
	s.tcpTotal++
	s.tcpMtx.Unlock()

	st.mtx.Lock()
	if st.tcpConns >= s.cfg.MaxTCPConnsPerSource {
		st.mtx.Unlock()
		s.releaseTCPTotal()
		return false
	}
	st.tcpConns++
	st.mtx.Unlock()

	return true
}

// releaseTCP gives back the slots reserved by acquireTCP.
func (s *Server) releaseTCP(src netip.Addr) {
	s.srcMtx.Lock()
	st, ok := s.sources[src]
	s.srcMtx.Unlock()
	if ok {
		st.mtx.Lock()
		st.tcpConns--
		st.mtx.Unlock()
	}
	s.releaseTCPTotal()
}

func (s *Server) releaseTCPTotal() {
	s.tcpMtx.Lock()
	s.tcpTotal--
	s.tcpMtx.Unlock()
}

// limitedListener only hands connections of containers that have a
// policy to the DNS server and caps how many each of them can hold.
// Connections that are refused are closed right after they were accepted,
// before the DNS server reads a single byte from them.
type limitedListener struct {
	net.Listener
	s *Server
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		// the source address identifies the container, see Policy
		ta, ok := c.RemoteAddr().(*net.TCPAddr)
		var src netip.Addr
		if ok {
			src, ok = netip.AddrFromSlice(ta.IP)
			src = src.Unmap()
		}
		if !ok || !l.s.acquireTCP(src) {
			if l.s.logOK(src) {
				l.s.logger.Warn("closing TCP connection over the limit or from an unmanaged source", zap.Stringer("source", src))
			}
			_ = c.Close()
			continue
		}

		return &trackedConn{Conn: c, release: func() { l.s.releaseTCP(src) }}, nil
	}
}

// trackedConn gives the connection's slots back exactly once when it is
// closed, however many times Close is called.
type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.release)

	return c.Conn.Close()
}
