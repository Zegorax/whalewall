// Command fakedns is an authoritative DNS server for the end-to-end
// tests. It serves records from a zone file and logs every query so
// tests can assert which names reached the upstream.
//
// Zone file lines: NAME TYPE TTL VALUE. A NAME starting with "*." matches
// every name below the suffix, at any depth.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type record struct {
	name  string
	rtype uint16
	ttl   uint32
	value string
}

type zone struct {
	records []record
}

func loadZone(path string) (*zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	z := &zone{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return nil, fmt.Errorf("invalid zone line %q", line)
		}
		rtype, ok := dns.StringToType[fields[1]]
		if !ok {
			return nil, fmt.Errorf("invalid record type in %q", line)
		}
		ttl, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid TTL in %q: %w", line, err)
		}
		z.records = append(z.records, record{
			name:  strings.ToLower(strings.TrimSuffix(fields[0], ".")),
			rtype: rtype,
			ttl:   uint32(ttl),
			value: fields[3],
		})
	}

	return z, sc.Err()
}

// lookup returns the records that apply to name and whether the name exists.
func (z *zone) lookup(name string) ([]record, bool) {
	var exact, wild []record
	for _, r := range z.records {
		switch {
		case r.name == name:
			exact = append(exact, r)
		case strings.HasPrefix(r.name, "*.") && strings.HasSuffix(name, r.name[1:]):
			wild = append(wild, r)
		}
	}
	if len(exact) != 0 {
		return exact, true
	}
	return wild, len(wild) != 0
}

type server struct {
	zone   *zone
	logMtx sync.Mutex
	logf   *os.File
}

func (s *server) logQuery(w dns.ResponseWriter, q dns.Question) {
	host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	s.logMtx.Lock()
	defer s.logMtx.Unlock()
	fmt.Fprintf(s.logf, "%d %s %s %s\n", time.Now().Unix(), host, strings.ToLower(q.Name), dns.TypeToString[q.Qtype])
}

func (s *server) answer(resp *dns.Msg, name string, qtype uint16, depth int) {
	records, _ := s.zone.lookup(name)
	for _, r := range records {
		hdr := fmt.Sprintf("%s. %d IN %s %s", name, r.ttl, dns.TypeToString[r.rtype], r.value)
		switch {
		case r.rtype == dns.TypeCNAME && qtype != dns.TypeCNAME:
			rr, err := dns.NewRR(hdr)
			if err != nil {
				continue
			}
			resp.Answer = append(resp.Answer, rr)
			if depth < 8 {
				s.answer(resp, strings.ToLower(strings.TrimSuffix(r.value, ".")), qtype, depth+1)
			}
		case r.rtype == qtype:
			rr, err := dns.NewRR(hdr)
			if err != nil {
				continue
			}
			resp.Answer = append(resp.Answer, rr)
		}
	}
}

func (s *server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	if len(req.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		w.WriteMsg(resp)
		return
	}

	q := req.Question[0]
	s.logQuery(w, q)
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if _, ok := s.zone.lookup(name); !ok {
		resp.Rcode = dns.RcodeNameError
		w.WriteMsg(resp)
		return
	}
	s.answer(resp, name, q.Qtype, 0)
	w.WriteMsg(resp)
}

func main() {
	zonePath := flag.String("zone", "zone.txt", "zone file")
	logPath := flag.String("log", "queries.log", "query log file")
	addrs := flag.String("listen", "127.0.0.1:5300", "comma-separated listen addresses")
	flag.Parse()

	z, err := loadZone(*zonePath)
	if err != nil {
		log.Fatal(err)
	}
	logf, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	s := &server{zone: z, logf: logf}

	errCh := make(chan error, 8)
	for _, addr := range strings.Split(*addrs, ",") {
		for _, network := range []string{"udp", "tcp"} {
			srv := &dns.Server{Addr: addr, Net: network, Handler: s}
			go func() { errCh <- srv.ListenAndServe() }()
		}
	}
	log.Fatal(<-errCh)
}
