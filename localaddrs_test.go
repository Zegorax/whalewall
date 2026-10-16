package whalewall

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/matryer/is"
)

func TestLocalAddrsContains(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	var loads atomic.Int32
	l := &localAddrs{load: func(context.Context) ([]netip.Addr, []netip.Prefix, error) {
		loads.Add(1)
		return []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("fd00::1")},
			[]netip.Prefix{netip.MustParsePrefix("10.98.0.0/24"), netip.MustParsePrefix("fd00:99::/64")}, nil
	}}

	for _, a := range []string{"192.0.2.2", "10.98.0.1", "10.98.0.200", "fd00::1", "fd00:99::7", "::ffff:192.0.2.2"} {
		is.True(l.contains(netip.MustParseAddr(a))) // a is local
	}
	for _, a := range []string{"192.0.2.3", "10.98.1.1", "203.0.113.5", "2001:db8::1", "fd00:98::1"} {
		is.True(!l.contains(netip.MustParseAddr(a))) // a is not local
	}
	is.Equal(loads.Load(), int32(1)) // cached

	// a nil checker never rejects
	var none *localAddrs
	is.True(!none.contains(netip.MustParseAddr("192.0.2.2")))
}

func TestLocalAddrsRefreshAndErrors(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	var fail atomic.Bool
	l := &localAddrs{load: func(context.Context) ([]netip.Addr, []netip.Prefix, error) {
		if fail.Load() {
			return nil, nil, errors.New("docker is down")
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.2")}, nil, nil
	}}
	is.True(l.contains(netip.MustParseAddr("192.0.2.2")))

	// a failing refresh keeps what was known
	fail.Store(true)
	l.mtx.Lock()
	l.expires = time.Now().Add(-time.Second)
	l.mtx.Unlock()
	is.True(l.contains(netip.MustParseAddr("192.0.2.2")))
}

func TestLoadLocalAddrsFromDocker(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	env := newIPv6TestEnv(t, false, false)
	cli, ok := env.r.dockerCli.(*mockDockerClient)
	is.True(ok)
	cli.networks = []types.NetworkResource{
		{Name: "bridge", Driver: "bridge", IPAM: network.IPAM{Config: []network.IPAMConfig{{Subnet: "172.17.0.0/16", Gateway: "172.17.0.1"}}}},
		{Name: "app", Driver: "bridge", IPAM: network.IPAM{Config: []network.IPAMConfig{
			{Subnet: "10.98.0.0/24", Gateway: "10.98.0.1"},
			{Subnet: "fd00:99::/64", Gateway: "fd00:99::1"},
		}}},
		// a macvlan network is a real LAN that rules may allow
		{Name: "lan", Driver: "macvlan", IPAM: network.IPAM{Config: []network.IPAMConfig{{Subnet: "192.168.1.0/24", Gateway: "192.168.1.1"}}}},
		{Name: "none", Driver: "null"},
	}

	env.r.interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.0.2.2"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
			&net.IPAddr{IP: net.ParseIP("::ffff:198.51.100.7")},
		}, nil
	}
	l := &localAddrs{load: env.r.loadLocalAddrs}
	for _, a := range []string{"192.0.2.2", "fe80::1", "198.51.100.7"} {
		is.True(l.contains(netip.MustParseAddr(a))) // a is an address of the host
	}
	for _, a := range []string{"172.17.0.1", "10.98.0.1", "fd00:99::1"} {
		is.True(l.contains(netip.MustParseAddr(a))) // a is the gateway of a Docker bridge network
	}
	for _, a := range []string{"172.17.5.5", "10.98.0.77", "fd00:99::abcd", "192.168.1.1", "192.168.1.50", "8.8.8.8", "172.18.0.1"} {
		is.True(!l.contains(netip.MustParseAddr(a))) // a is not
	}
}
