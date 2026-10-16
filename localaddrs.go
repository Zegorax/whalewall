package whalewall

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"go.uber.org/zap"
)

const localAddrTTL = 10 * time.Second

// localAddrs answers whether an address belongs to the host or to a
// Docker network. A name a container is allowed to resolve must never
// lead to those: the host's services are not what a domain
// rule is meant to open, and traffic that a rule accepts is not
// checked against the destination's own rules.
type localAddrs struct {
	logger *zap.Logger
	load   func(ctx context.Context) ([]netip.Addr, []netip.Prefix, error)

	mtx      sync.Mutex
	expires  time.Time
	addrs    map[netip.Addr]struct{}
	prefixes []netip.Prefix
}

func (l *localAddrs) contains(a netip.Addr) bool {
	if l == nil {
		return false
	}

	l.mtx.Lock()
	defer l.mtx.Unlock()

	if time.Now().After(l.expires) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		addrs, prefixes, err := l.load(ctx)
		cancel()
		if err != nil {
			if l.logger != nil {
				l.logger.Warn("error listing the host's and Docker networks' addresses", zap.Error(err))
			}
			// keep what is known and retry soon
			l.expires = time.Now().Add(time.Second)
		} else {
			l.addrs = make(map[netip.Addr]struct{}, len(addrs))
			for _, addr := range addrs {
				l.addrs[addr.Unmap()] = struct{}{}
			}
			l.prefixes = prefixes
			l.expires = time.Now().Add(localAddrTTL)
		}
	}

	a = a.Unmap()
	if _, ok := l.addrs[a]; ok {
		return true
	}
	for _, p := range l.prefixes {
		if p.Contains(a) {
			return true
		}
	}

	return false
}

// loadLocalAddrs lists the host's addresses and the gateways of Docker's
// bridge networks.
func (r *RuleManager) loadLocalAddrs(ctx context.Context) ([]netip.Addr, []netip.Prefix, error) {
	ifAddrs, err := r.interfaceAddrs()
	if err != nil {
		return nil, nil, fmt.Errorf("error listing the host's addresses: %w", err)
	}
	addrs := make([]netip.Addr, 0, len(ifAddrs))
	for _, ifAddr := range ifAddrs {
		var ip net.IP
		switch a := ifAddr.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			addrs = append(addrs, addr.Unmap())
		}
	}

	networks, err := r.dockerCli.NetworkList(ctx, types.NetworkListOptions{})
	if err != nil {
		return addrs, nil, err
	}
	for _, n := range networks {
		// bridge networks are local to this host; others (macvlan, ...)
		// can be real LANs that rules may legitimately allow. Only the
		// gateway, which is the host itself, is rejected: other containers
		// on a bridge are valid targets, so their subnets are not.
		if n.Driver != "bridge" {
			continue
		}
		for _, cfg := range n.IPAM.Config {
			if gw, err := netip.ParseAddr(cfg.Gateway); err == nil {
				addrs = append(addrs, gw)
			}
		}
	}

	return addrs, nil, nil

}
