package dnsproxy

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	defaultQueryRate            = 100.0
	defaultQueryBurst           = 200
	defaultMaxInflight          = 32
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
	mtx      sync.Mutex
	tokens   float64
	last     time.Time
	inflight int
	tcpConns int
	logTok   float64
	logLast  time.Time
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

func (s *Server) forgetSources(addrs []netip.Addr) {
	s.srcMtx.Lock()
	defer s.srcMtx.Unlock()
	for _, a := range addrs {
		delete(s.sources, a.Unmap())
	}
}

// admit decides whether a query of src is processed. The returned
// function must be called when the query is done.
func (s *Server) admit(src netip.Addr) (release func(), ok bool) {
	st := s.source(src)

	st.mtx.Lock()
	defer st.mtx.Unlock()

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

// logOK reports whether another line may be logged for src.
func (s *Server) logOK(src netip.Addr) bool {
	s.srcMtx.Lock()
	st, ok := s.sources[src]
	s.srcMtx.Unlock()
	if !ok {
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

// globalLog limits the log lines caused by sources that have no policy.
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

// acquireTCP reserves a connection slot for src.
func (s *Server) acquireTCP(src netip.Addr) bool {
	if _, ok := s.policy(src); !ok {
		return false
	}
	st := s.source(src)

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

type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.release)

	return c.Conn.Close()
}
