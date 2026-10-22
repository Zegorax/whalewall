package whalewall

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/network"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/capnspacehook/whalewall/dnsproxy"
)

// How domain rules work, in short: the rules of a container accept traffic
// to a timed set of addresses, which starts out empty. The container's DNS
// traffic is redirected (nftables DNAT) to the resolver in the dnsproxy
// package, listening on the gateway address of the container's network.
// When the container asks for a name one of its rules allows, the resolver
// puts the addresses of the answer into that rule's set, with a timeout,
// before it returns the answer. Names no rule allows are not resolved and
// never leave the host, so the container has no address to connect to.
const (
	// natTableName is the table the DNS redirect rules are in. It is
	// separate from Docker's tables so -clear and cleanup can remove it
	// without touching anything of Docker's.
	natTableName = "whalewall-nat"
	natChainName = "prerouting"
	// natPriority is just before Docker's own destination NAT rules
	natPriority = nftables.ChainPriority(-110)

	// domainSetPrefix starts the names of the sets of allowed addresses
	// (see domainSetName), so the sets of a container can be found again
	domainSetPrefix = "ww-"
	// dnsPort is the port containers send DNS queries to
	dnsPort = 53

	// defaultDNSPort is the port the resolver listens on, on the gateway
	// address of each network, unless DNSOptions.Port is set (-dns-port)
	defaultDNSPort = 5353
)

// DNSOptions enables and configures DNS filtering.
type DNSOptions struct {
	// Port is the port the resolver listens on.
	Port uint16
	// Upstreams are "host:port" addresses of upstream resolvers; if
	// empty the host's resolvers are used.
	Upstreams []string
	// MinTTL is the minimum time an address resolved from a domain stays
	// allowed.
	MinTTL time.Duration
	// Grace is added to the time an address stays allowed.
	Grace time.Duration
	// MaxTTL is the longest an address stays allowed, whatever TTL its
	// record has.
	MaxTTL time.Duration
}

// Option configures a [RuleManager].
type Option func(*RuleManager)

// WithIsolateInvalidRules isolates a container completely if its rules
// are invalid. Without it a container with invalid rules gets no rules at
// all and so is not restricted, an error is logged.
func WithIsolateInvalidRules() Option {
	return func(r *RuleManager) {
		r.isolateInvalid = true
	}
}

// WithDNS enables rules that allow traffic by domain name. Without it the
// resolver is not started, no NAT rules are created and a rule with
// "domains" is invalid (the container's rules are then handled like any
// other invalid rules, see WithIsolateInvalidRules).
func WithDNS(opts DNSOptions) Option {
	return func(r *RuleManager) {
		r.dnsEnabled = true
		r.dnsOpts = opts
		if r.dnsOpts.Port == 0 {
			r.dnsOpts.Port = defaultDNSPort
		}
	}
}

// dnsServer is the part of [dnsproxy.Server] the rule manager uses. It is an
// interface so tests can replace the resolver.
type dnsServer interface {
	Acquire(addr netip.AddrPort) error
	Release(addr netip.AddrPort)
	Register(addrs []netip.Addr, p *dnsproxy.Policy)
	Unregister(addrs []netip.Addr, p *dnsproxy.Policy)
	Close()
}

// domainPolicy is the DNS policy of a container with domain rules. It
// connects the resolver (which names are allowed, from the rules) to the
// firewall (the sets those names' addresses are added to).
type domainPolicy struct {
	id   string
	name string
	// rules are the container's rules that have domains
	rules []domainRule
	// addrs are the container addresses the policy is registered for
	addrs []netip.Addr
	// listeners are the resolver addresses acquired for the container
	listeners []netip.AddrPort
	// registered is the policy given to the resolver, nil until then
	registered *dnsproxy.Policy

	// live tracks the addresses in each set and when they expire, to
	// keep a container from filling kernel memory with them
	liveMtx sync.Mutex
	live    map[*nftables.Set]map[netip.Addr]time.Time
}

// maxSetAddrs is the number of addresses that can be allowed at the same
// time by one rule. A wildcard rule lets a container resolve names it
// controls, each with many addresses, and the kernel keeps every element
// until its TTL (up to -dns-max-ttl) ends.
const maxSetAddrs = 4096

var errTooManyAddrs = fmt.Errorf("more than %d addresses allowed by one rule", maxSetAddrs)

// reserve records addrs as allowed in set, or fails without recording
// anything if that would exceed maxSetAddrs. It keeps the expiry time of
// every address to count, as the kernel doesn't tell how many elements a set
// has. Adding an address that is already allowed only extends it. allowAddrs
// calls it before anything is added to the kernel, so a refused answer
// changes nothing.
func (p *domainPolicy) reserve(set *nftables.Set, addrs []dnsproxy.Resolved) error {
	p.liveMtx.Lock()
	defer p.liveMtx.Unlock()

	if p.live == nil {
		p.live = make(map[*nftables.Set]map[netip.Addr]time.Time)
	}
	m := p.live[set]
	if m == nil {
		m = make(map[netip.Addr]time.Time)
		p.live[set] = m
	}

	now := time.Now()
	fresh := 0
	for _, a := range addrs {
		if exp, ok := m[a.Addr]; !ok || now.After(exp) {
			fresh++
		}
	}
	// the common case is below the limit and doesn't need to clean up;
	// expired entries are only removed when they could make the difference
	if len(m)+fresh > maxSetAddrs {
		// forget what has expired and look again
		for a, exp := range m {
			if now.After(exp) {
				delete(m, a)
			}
		}
		fresh = 0
		for _, a := range addrs {
			if _, ok := m[a.Addr]; !ok {
				fresh++
			}
		}
		if len(m)+fresh > maxSetAddrs {
			return errTooManyAddrs
		}
	}
	// an address allowed twice keeps the later of the two expiry times
	for _, a := range addrs {
		if exp := now.Add(a.TTL); exp.After(m[a.Addr]) {
			m[a.Addr] = exp
		}
	}

	return nil
}

// domainRule is one rule with domains: the names it allows and, per IP
// family, the set that holds the addresses those names resolved to.
type domainRule struct {
	domains domainsList
	sets    map[*family]*nftables.Set
}

// hasDomainRules reports whether any output rule of cfg has domains, which
// is when the container needs the resolver.
func hasDomainRules(cfg config) bool {
	for _, rule := range cfg.Output {
		if len(rule.Domains) != 0 {
			return true
		}
	}
	return false
}

// domainSetName returns the name of the set holding the allowed
// addresses of a domain rule: the prefix, the first 12 characters of the
// container ID (what the chain names use as well) and the index of the rule
// in the container's rules. The trailing "4" is the IP family.
func domainSetName(id string, ruleIdx int) string {
	return fmt.Sprintf("%s%s-%d-4", domainSetPrefix, id[:12], ruleIdx)
}

// domainSetPrefixFor returns the start of the names of all sets of a
// container, whatever their rule index and family.
func domainSetPrefixFor(id string) string {
	return domainSetPrefix + id[:12] + "-"
}

// createDomainRules creates the set that holds the allowed addresses of
// a rule with domains and the rules that allow traffic to them. The rules
// are the normal ones for the rule's ports and protocol, with a lookup in
// the set in place of fixed destination addresses. Nothing is in the set
// yet, so until the container resolves an allowed name the rule accepts
// nothing. HasTimeout makes the kernel remove each address when its
// timeout, set in allowAddrs, ends.
func (r *RuleManager) createDomainRules(nfc firewallClient, logger *zap.Logger, st *famState, ruleIdx int, rule ruleDetails) ([]*nftables.Rule, error) {
	set := &nftables.Set{
		Table:      st.fam.table,
		Name:       domainSetName(rule.contID, ruleIdx),
		KeyType:    st.fam.addrKeyType,
		HasTimeout: true,
	}
	if err := nfc.AddSet(set, nil); err != nil {
		return nil, fmt.Errorf("error adding set %q: %w", set.Name, err)
	}
	// the set must exist before rules that use it are created
	if err := ignoringErr(nfc.Flush, syscall.EEXIST); err != nil {
		return nil, fmt.Errorf("error creating set %q: %w", set.Name, err)
	}
	if st.domainSets == nil {
		st.domainSets = make(map[int]*nftables.Set)
	}
	st.domainSets[ruleIdx] = set

	rule.domainSet = set
	var nftRules []*nftables.Rule
	for _, addr := range st.addrs {
		rule.addr = addr
		rules, err := createNFTRules(nfc, logger, rule)
		if err != nil {
			return nil, fmt.Errorf("error creating firewall rules: %w", err)
		}
		nftRules = append(nftRules, rules...)
	}

	return nftRules, nil
}

// cleanupDomainState removes the sets created for a container; used when
// creating the container's rules is canceled, together with the removal of
// its chain.
func (r *RuleManager) cleanupDomainState(nfc firewallClient, logger *zap.Logger, st *famState) {
	for _, set := range st.domainSets {
		nfc.DelSet(set)
		if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
			logger.Error("error deleting set", zap.String("set.name", set.Name), zap.Error(err))
		}
	}
}

// deleteDomainSets removes all sets of a container, found by name. Unlike
// cleanupDomainState it works after a restart of whalewall too, when only
// the container's ID is known.
func (r *RuleManager) deleteDomainSets(nfc firewallClient, logger *zap.Logger, id string) {
	prefix := domainSetPrefixFor(id)
	for _, fam := range families {
		sets, err := nfc.GetSets(fam.table)
		if err != nil {
			logger.Debug("error listing sets", zap.Stringer("family", fam), zap.Error(err))
			continue
		}
		for _, set := range sets {
			if len(set.Name) < len(prefix) || set.Name[:len(prefix)] != prefix {
				continue
			}
			nfc.DelSet(set)
			if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
				logger.Error("error deleting set", zap.String("set.name", set.Name), zap.Error(err))
			}
		}
	}
}

// natFamilyTable and natFamilyChain describe the NAT table and chain of an
// IP family. The parameter selects the family.
func natFamilyTable(*family) *nftables.Table {
	return &nftables.Table{Name: natTableName, Family: nftables.TableFamilyIPv4}
}

func natFamilyChain(fam *family) *nftables.Chain {
	return &nftables.Chain{
		Name:     natChainName,
		Table:    natFamilyTable(fam),
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(natPriority),
	}
}

// ensureNAT creates the table and chain DNS queries are redirected in.
func (r *RuleManager) ensureNAT(nfc firewallClient, fam *family) error {
	nfc.AddTable(natFamilyTable(fam))
	nfc.AddChain(natFamilyChain(fam))
	if err := ignoringErr(nfc.Flush, syscall.EEXIST); err != nil {
		return fmt.Errorf("error creating %s NAT table: %w", fam, err)
	}

	return nil
}

// createDNATRules returns rules that redirect DNS queries of a container
// to the resolver listening on gateway, one for UDP and one for TCP. Only
// packets from the container's own address and to port 53 are redirected,
// to whatever address they were sent to, so the container doesn't need to
// know the resolver's address and DNS to any server ends up at the filter.
func createDNATRules(fam *family, id string, contAddr, gateway []byte, port uint16) []*nftables.Rule {
	chain := natFamilyChain(fam)
	nfproto := uint32(unix.NFPROTO_IPV4)

	// the rules are tagged with the container ID (UserData) so they can be
	// found and deleted with the container
	rules := make([]*nftables.Rule, 0, 2)
	for _, proto := range []int{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		exprs := matchAddrExprs(contAddr, fam.srcOffset)
		exprs = append(exprs, matchProtoExprs(proto)...)
		exprs = append(exprs, matchPortExprs(dnsPort, dstPortOffset)...)
		exprs = append(exprs,
			&expr.Counter{},
			// [ immediate reg 1 <gateway> ]
			&expr.Immediate{Register: 1, Data: gateway},
			// [ immediate reg 2 <port> ]
			&expr.Immediate{Register: 2, Data: binary.BigEndian.AppendUint16(nil, port)},
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      nfproto,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		)
		rules = append(rules, &nftables.Rule{
			Table:    chain.Table,
			Chain:    chain,
			Exprs:    exprs,
			UserData: []byte(id),
		})
	}

	return rules
}

// deleteDNATRules removes the NAT rules of a container.
func (r *RuleManager) deleteDNATRules(nfc firewallClient, logger *zap.Logger, id string) {
	for _, fam := range families {
		chain := natFamilyChain(fam)
		rules, err := nfc.GetRules(chain.Table, chain)
		if err != nil {
			// the table doesn't exist if DNS filtering was never used
			continue
		}
		deleteRulesFromContainer(logger, nfc, rules, id)
	}
}

// dnsEndpoint is where one address of a container sends its DNS queries:
// the gateway of the network the address is on.
type dnsEndpoint struct {
	fam       *family
	netName   string
	contAddr  []byte
	gateway   netip.Addr
	gatewayBy []byte
}

// dnsEndpoints returns the resolver address for every address of the
// container. The resolver listens on the gateway address of the network
// because that address is the host as the container sees it, and exists
// before the container does, so no address has to be chosen per container.
// Networks without a gateway address are skipped.
func dnsEndpoints(st *famState, networks map[string]*network.EndpointSettings) []dnsEndpoint {
	eps := make([]dnsEndpoint, 0, len(st.addrs))
	for netName, contAddr := range st.addrs {
		settings := networks[netName]
		if settings == nil {
			continue
		}
		gateway, err := netip.ParseAddr(settings.Gateway)
		if err != nil {
			continue
		}
		eps = append(eps, dnsEndpoint{
			fam:       st.fam,
			netName:   netName,
			contAddr:  contAddr,
			gateway:   gateway,
			gatewayBy: addrBytes(gateway),
		})
	}

	return eps
}

// createDNSAccessRules returns rules that allow a container to reach
// the resolver on its network's gateway, over UDP and TCP on the resolver's
// port. The redirect changes the destination of DNS queries to that
// address and port; the container's rules still have to accept the
// result.
func (r *RuleManager) createDNSAccessRules(nfc firewallClient, logger *zap.Logger, id string, st *famState, eps []dnsEndpoint) ([]*nftables.Rule, error) {
	var nftRules []*nftables.Rule
	for _, ep := range eps {
		for _, proto := range []protocol{udp, tcp} {
			rules, err := createNFTRules(nfc, logger, ruleDetails{
				addr: ep.contAddr,
				cfg: ruleConfig{
					IPs:      []addrOrRange{{addr: ep.gateway}},
					Proto:    proto,
					DstPorts: []rulePorts{{single: r.dnsOpts.Port}},
				},
				chain:  st.chain,
				contID: id,
			})
			if err != nil {
				return nil, fmt.Errorf("error creating firewall rules: %w", err)
			}
			nftRules = append(nftRules, rules...)
		}
	}

	return nftRules, nil
}

// registerDNS makes the resolver answer queries of a container
// according to its domain rules, and redirects the container's DNS
// traffic to it. The steps are: build the policy from the rules, install
// the redirect, start listening on the gateways, and finally register the
// policy, which is the point after which queries of the container are
// answered.
func (r *RuleManager) registerDNS(nfc firewallClient, id, name string, cfg config, states []*famState, endpoints []dnsEndpoint) error {
	if !hasDomainRules(cfg) {
		return nil
	}

	policy := &domainPolicy{id: id, name: name}
	for ruleIdx, rule := range cfg.Output {
		if len(rule.Domains) == 0 {
			continue
		}
		dr := domainRule{domains: rule.Domains, sets: make(map[*family]*nftables.Set)}
		for _, st := range states {
			if set, ok := st.domainSets[ruleIdx]; ok {
				dr.sets[st.fam] = set
			}
		}
		policy.rules = append(policy.rules, dr)
	}

	// redirect DNS traffic to the resolver, one family at a time
	for _, fam := range families {
		var famEndpoints []dnsEndpoint
		for _, ep := range endpoints {
			if ep.fam == fam {
				famEndpoints = append(famEndpoints, ep)
			}
		}
		if len(famEndpoints) == 0 {
			continue
		}
		if err := r.ensureNAT(nfc, fam); err != nil {
			return err
		}

		// Replace the rules of a previous run instead of comparing them
		// to the new ones: add the new rules first so there is no window
		// without a redirect.
		chain := natFamilyChain(fam)
		current, err := nfc.GetRules(chain.Table, chain)
		if err != nil {
			return fmt.Errorf("error getting rules of chain %q: %w", chain.Name, err)
		}
		var stale []*nftables.Rule
		for _, rule := range current {
			if string(rule.UserData) == id {
				stale = append(stale, rule)
			}
		}
		for _, ep := range famEndpoints {
			for _, rule := range createDNATRules(fam, id, ep.contAddr, ep.gatewayBy, r.dnsOpts.Port) {
				nfc.AddRule(rule)
			}
		}
		if err := nfc.Flush(); err != nil {
			return fmt.Errorf("error creating DNS redirect rules: %w", err)
		}
		for _, rule := range stale {
			if err := nfc.DelRule(rule); err != nil {
				return fmt.Errorf("error deleting stale DNS redirect rule: %w", err)
			}
			if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
				return fmt.Errorf("error deleting stale DNS redirect rule: %w", err)
			}
		}
	}

	// the resolver tells containers apart by source address, so the
	// policy is registered for every address of the container, and the
	// resolver listens on every gateway address
	for _, ep := range endpoints {
		addr, _ := netip.AddrFromSlice(ep.contAddr)
		policy.addrs = append(policy.addrs, addr)

		listener := netip.AddrPortFrom(ep.gateway, r.dnsOpts.Port)
		if err := r.dns.Acquire(listener); err != nil {
			r.unregisterDNS(id)
			return fmt.Errorf("error starting resolver: %w", err)
		}
		policy.listeners = append(policy.listeners, listener)
	}

	// the host's addresses on the container's networks must never be
	// reachable through a name, a rebinding attack would make a permitted
	// name point at services on the host
	gateways := make(map[netip.Addr]bool, len(endpoints))
	for _, ep := range endpoints {
		gateways[ep.gateway] = true
	}

	// Match decides which names are resolved at all; Allow is called with
	// the addresses of an answer to a name that matched.
	registered := &dnsproxy.Policy{
		Name:  name,
		Match: policy.matches,
		Reject: func(a netip.Addr) bool {
			return gateways[a] || r.local.contains(a)
		},
		Allow: func(ctx context.Context, qname string, addrs []dnsproxy.Resolved) error {
			return r.allowAddrs(policy, qname, addrs)
		},
	}

	policy.registered = registered

	r.dnsMtx.Lock()
	if old, ok := r.dnsPolicies[id]; ok {
		// rules are being recreated, drop what the previous call acquired
		r.releaseDNSLocked(old)
	}
	r.dnsPolicies[id] = policy
	// registering under the lock keeps a concurrent removal of the
	// container from running between the two
	r.dns.Register(policy.addrs, registered)
	r.dnsMtx.Unlock()

	return nil
}

// matches reports whether any rule of the container allows name.
func (p *domainPolicy) matches(name string) bool {
	for _, rule := range p.rules {
		if rule.domains.matches(name) {
			return true
		}
	}
	return false
}

// allowAddrs adds the addresses an allowed name resolved to to the sets
// of the rules that match the name. Only the rules whose domains match are
// opened: a name allowed by one rule doesn't open the destinations of
// another rule of the container. The limit is checked for all sets before
// anything is added, and the elements are written in one flush, so the
// firewall already allows the addresses when the resolver returns the
// answer; if this fails the container gets an error instead of an
// address it can't use.
func (r *RuleManager) allowAddrs(p *domainPolicy, qname string, addrs []dnsproxy.Resolved) error {
	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	var added bool
	for _, rule := range p.rules {
		if !rule.domains.matches(qname) {
			continue
		}
		for _, fam := range families {
			var famAddrs []dnsproxy.Resolved
			for _, a := range addrs {
				if familyOfAddr(a.Addr) == fam {
					famAddrs = append(famAddrs, a)
				}
			}
			if set, ok := rule.sets[fam]; ok && len(famAddrs) != 0 {
				if err := p.reserve(set, famAddrs); err != nil {
					return err
				}
			}
		}
		for _, a := range addrs {
			set, ok := rule.sets[familyOfAddr(a.Addr)]
			if !ok {
				continue
			}
			err := nfc.SetAddElements(set, []nftables.SetElement{{
				Key:     addrBytes(a.Addr),
				Timeout: a.TTL,
			}})
			if err != nil {
				return fmt.Errorf("error marshaling set elements: %w", err)
			}
			added = true
		}
	}
	if !added {
		return nil
	}
	if err := ignoringErr(nfc.Flush, syscall.EEXIST); err != nil {
		return fmt.Errorf("error adding addresses to set: %w", err)
	}

	return nil
}

// unregisterDNS stops the resolver from answering queries of a container
// and removes its redirect rules.
func (r *RuleManager) unregisterDNS(id string) {
	r.dnsMtx.Lock()
	defer r.dnsMtx.Unlock()

	if p, ok := r.dnsPolicies[id]; ok {
		r.releaseDNSLocked(p)
		delete(r.dnsPolicies, id)
	}
}

// releaseDNSLocked unregisters a policy and gives back the resolver
// addresses it acquired. dnsMtx must be held.
func (r *RuleManager) releaseDNSLocked(p *domainPolicy) {
	r.dns.Unregister(p.addrs, p.registered)
	for _, l := range p.listeners {
		r.dns.Release(l)
	}
}

// initDNS creates the resolver. It is created when whalewall starts but
// only listens once a container with domain rules needs an address, see
// registerDNS. Upstream servers are the ones given with -dns-upstream, or
// the host's from /etc/resolv.conf.
func (r *RuleManager) initDNS() error {
	upstreams := r.dnsOpts.Upstreams
	if len(upstreams) == 0 {
		upstreams = dnsproxy.SystemUpstreams("/etc/resolv.conf")
	}
	srv, err := dnsproxy.New(r.logger, dnsproxy.Config{
		Upstreams: upstreams,
		MinTTL:    r.dnsOpts.MinTTL,
		Grace:     r.dnsOpts.Grace,
		MaxTTL:    r.dnsOpts.MaxTTL,
	})
	if err != nil {
		return fmt.Errorf("error creating resolver: %w", err)
	}
	r.dns = srv
	r.dnsPolicies = make(map[string]*domainPolicy)
	r.local = &localAddrs{logger: r.logger, load: r.loadLocalAddrs}
	r.logger.Info("DNS filtering enabled", zap.Strings("dns.upstreams", upstreams), zap.Uint16("dns.port", r.dnsOpts.Port))

	return nil
}

// clearNAT removes the tables created for DNS redirection. It also runs
// for a whalewall started without -dns, because a previous run may have
// created them.
func (r *RuleManager) clearNAT() error {
	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}
	var errs []error
	for _, fam := range families {
		nfc.DelTable(natFamilyTable(fam))
		if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
