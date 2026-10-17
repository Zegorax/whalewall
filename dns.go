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

const (
	natTableName = "whalewall-nat"
	natChainName = "prerouting"
	// natPriority is just before Docker's own destination NAT rules
	natPriority = nftables.ChainPriority(-110)

	domainSetPrefix = "ww-"
	dnsPort         = 53

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

// WithDNS enables rules that allow traffic by domain name.
func WithDNS(opts DNSOptions) Option {
	return func(r *RuleManager) {
		r.dnsEnabled = true
		r.dnsOpts = opts
		if r.dnsOpts.Port == 0 {
			r.dnsOpts.Port = defaultDNSPort
		}
	}
}

// dnsServer is the part of [dnsproxy.Server] the rule manager uses.
type dnsServer interface {
	Acquire(addr netip.AddrPort) error
	Release(addr netip.AddrPort)
	Register(addrs []netip.Addr, p *dnsproxy.Policy)
	Unregister(addrs []netip.Addr, p *dnsproxy.Policy)
	Close()
}

// domainPolicy is the DNS policy of a container with domain rules.
type domainPolicy struct {
	id    string
	name  string
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
// anything if that would exceed maxSetAddrs.
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
	for _, a := range addrs {
		if exp := now.Add(a.TTL); exp.After(m[a.Addr]) {
			m[a.Addr] = exp
		}
	}

	return nil
}

type domainRule struct {
	domains domainsList
	sets    map[*family]*nftables.Set
}

func hasDomainRules(cfg config) bool {
	for _, rule := range cfg.Output {
		if len(rule.Domains) != 0 {
			return true
		}
	}
	return false
}

// domainSetName returns the name of the set holding the allowed
// addresses of a domain rule.
func domainSetName(id string, ruleIdx int, fam *family) string {
	suffix := "4"
	if fam.v6 {
		suffix = "6"
	}
	return fmt.Sprintf("%s%s-%d-%s", domainSetPrefix, id[:12], ruleIdx, suffix)
}

func domainSetPrefixFor(id string) string {
	return domainSetPrefix + id[:12] + "-"
}

// createDomainRules creates the set that holds the allowed addresses of
// a rule with domains and the rules that allow traffic to them.
func (r *RuleManager) createDomainRules(nfc firewallClient, logger *zap.Logger, st *famState, ruleIdx int, rule ruleDetails) ([]*nftables.Rule, error) {
	set := &nftables.Set{
		Table:      st.fam.table,
		Name:       domainSetName(rule.contID, ruleIdx, st.fam),
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

// cleanupDomainState removes the sets created for a container.
func (r *RuleManager) cleanupDomainState(nfc firewallClient, logger *zap.Logger, st *famState) {
	for _, set := range st.domainSets {
		nfc.DelSet(set)
		if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
			logger.Error("error deleting set", zap.String("set.name", set.Name), zap.Error(err))
		}
	}
}

// deleteDomainSets removes all sets of a container.
func (r *RuleManager) deleteDomainSets(nfc firewallClient, logger *zap.Logger, id string) {
	prefix := domainSetPrefixFor(id)
	for _, fam := range families {
		sets, err := nfc.GetSets(fam.table)
		if err != nil {
			// the table may not exist, for example for IPv6
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

func natFamilyTable(fam *family) *nftables.Table {
	t := &nftables.Table{Name: natTableName, Family: nftables.TableFamilyIPv4}
	if fam.v6 {
		t.Family = nftables.TableFamilyIPv6
	}
	return t
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
// to the resolver listening on gateway.
func createDNATRules(fam *family, id string, contAddr, gateway []byte, port uint16) []*nftables.Rule {
	chain := natFamilyChain(fam)
	nfproto := uint32(unix.NFPROTO_IPV4)
	if fam.v6 {
		nfproto = unix.NFPROTO_IPV6
	}

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

type dnsEndpoint struct {
	fam       *family
	netName   string
	contAddr  []byte
	gateway   netip.Addr
	gatewayBy []byte
}

// dnsEndpoints returns the resolver address for every address of the
// container.
func dnsEndpoints(st *famState, networks map[string]*network.EndpointSettings) []dnsEndpoint {
	eps := make([]dnsEndpoint, 0, len(st.addrs))
	for netName, contAddr := range st.addrs {
		settings := networks[netName]
		if settings == nil {
			continue
		}
		gw := settings.Gateway
		if st.fam.v6 {
			gw = settings.IPv6Gateway
		}
		gateway, err := netip.ParseAddr(gw)
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
// the resolver on its network's gateway.
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
// traffic to it.
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

	// redirect DNS traffic to the resolver
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

	registered := &dnsproxy.Policy{
		Name:    name,
		Match:   policy.matches,
		HasIPv6: hasFamily(states, family6),
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

func hasFamily(states []*famState, fam *family) bool {
	for _, st := range states {
		if st.fam == fam {
			return true
		}
	}
	return false
}

func (p *domainPolicy) matches(name string) bool {
	for _, rule := range p.rules {
		if rule.domains.matches(name) {
			return true
		}
	}
	return false
}

// allowAddrs adds the addresses an allowed name resolved to to the sets
// of the rules that match the name.
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

func (r *RuleManager) releaseDNSLocked(p *domainPolicy) {
	r.dns.Unregister(p.addrs, p.registered)
	for _, l := range p.listeners {
		r.dns.Release(l)
	}
}

// initDNS creates the resolver.
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

// clearNAT removes the tables created for DNS redirection.
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
