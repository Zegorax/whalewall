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
	table          *nftables.Table
	whalewallChain *nftables.Chain
	addrSet        *nftables.Set

	addrKeyType nftables.SetDatatype
	addrLen     uint32
	srcOffset   uint32
	dstOffset   uint32
}

var (
	family4 = &family{
		table:          filterTable,
		whalewallChain: whalewallChain,
		addrSet:        containerAddrSet,
		addrKeyType:    nftables.TypeIPAddr,
		addrLen:        4,
		srcOffset:      srcAddrOffset,
		dstOffset:      dstAddrOffset,
	}

	families = []*family{family4}

	srcJumpRule = family4.jumpRule(true)
	dstJumpRule = family4.jumpRule(false)
)

func (f *family) String() string {
	return "ipv4"
}

// familyOfTable returns the family a table belongs to.
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

// addrBytes returns the address in the form it has in a packet header.
func addrBytes(a netip.Addr) []byte {
	if a.Is4In6() {
		a = a.Unmap()
	}
	return a.AsSlice()
}

// filterIPs returns the entries of ips that belong to f.
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
