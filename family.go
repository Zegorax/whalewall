package whalewall

import (
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// family describes the nftables objects whalewall manages for one IP
// family. Docker keeps the rules of each IP family in separate tables
// that share the same name, so every object exists once per family.
type family struct {
	// table is Docker's filter table of this family
	table *nftables.Table
	// whalewallChain is whalewall's chain in that table; Docker's chains
	// jump to it
	whalewallChain *nftables.Chain
	// addrSet maps the addresses of containers to their chains
	addrSet *nftables.Set

	// addrKeyType and addrLen describe an address in sets and in packets;
	// srcOffset and dstOffset are where the source and destination
	// addresses are in the network header
	addrKeyType nftables.SetDatatype
	addrLen     uint32
	srcOffset   uint32
	dstOffset   uint32
}

var (
	// family4 is built from the existing IPv4 variables in base.go, so the
	// objects (and the rules created for them) are the same as before the
	// family abstraction existed
	family4 = &family{
		table:          filterTable,
		whalewallChain: whalewallChain,
		addrSet:        containerAddrSet,
		addrKeyType:    nftables.TypeIPAddr,
		addrLen:        4,
		srcOffset:      srcAddrOffset,
		dstOffset:      dstAddrOffset,
	}

	// families are the IP families whalewall manages; code that has to act
	// on all of them loops over this
	families = []*family{family4}

	// srcJumpRule and dstJumpRule jump to a container's chain when a packet
	// comes from or goes to one of the addresses in the address set
	srcJumpRule = family4.jumpRule(true)
	dstJumpRule = family4.jumpRule(false)
)

// String returns the name of the family for logs and error messages.
func (f *family) String() string {
	return "ipv4"
}

// familyOfTable returns the family a table belongs to. Only IPv4 is managed
// for now, so it is always family4.
func familyOfTable(*nftables.Table) *family {
	return family4
}

// familyOfAddr returns the family an address belongs to, or nil if
// whalewall doesn't manage it.
func familyOfAddr(a netip.Addr) *family {
	if a.Is4() || a.Is4In6() {
		return family4
	}
	return nil
}

// addrBytes returns the address in the form it has in a packet header:
// 4 bytes for IPv4. An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is
// converted to its IPv4 form first, as that is what such a packet carries.
func addrBytes(a netip.Addr) []byte {
	if a.Is4In6() {
		a = a.Unmap()
	}
	return a.AsSlice()
}

// filterIPs returns the entries of ips that belong to f. A range belongs to
// the family of its first address. Entries of a family that isn't managed
// are dropped, so a rule that only has those matches nothing.
func (f *family) filterIPs(ips []addrOrRange) []addrOrRange {
	var out []addrOrRange
	for _, ip := range ips {
		if addr, ok := ip.Addr(); ok {
			if familyOfAddr(addr) == f {
				out = append(out, ip)
			}
		} else if from, _, ok := ip.Range(); ok {
			if familyOfAddr(from) == f {
				out = append(out, ip)
			}
		}
	}

	return out
}

// jumpRule returns the rule in the whalewall chain that jumps to a
// container chain by looking up the source or destination address.
func (f *family) jumpRule(src bool) *nftables.Rule {
	offset := f.dstOffset
	if src {
		offset = f.srcOffset
	}
	return &nftables.Rule{
		Table: f.table,
		Chain: f.whalewallChain,
		Exprs: []expr.Any{
			// [ payload load ...b @ network header + ... => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           f.addrLen,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        offset,
				DestRegister:  1,
			},
			// [ lookup reg 1 set ... dreg 0 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        containerAddrSetName,
				DestRegister:   0,
				IsDestRegSet:   true,
			},
		},
	}
}
