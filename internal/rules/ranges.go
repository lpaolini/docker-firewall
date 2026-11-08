package rules

import (
	"net/netip"
	"slices"
)

// Range is an inclusive address range within one address family.
type Range struct{ Lo, Hi netip.Addr }

// PrefixRange returns the addresses covered by p.
func PrefixRange(p netip.Prefix) Range {
	p = p.Masked()
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	hi, _ := netip.AddrFromSlice(b)
	return Range{p.Addr(), hi}
}

// AddrRange returns the range holding only a.
func AddrRange(a netip.Addr) Range { return Range{a, a} }

// Is4 reports whether r is an IPv4 range.
func (r Range) Is4() bool { return r.Lo.Is4() }

// String renders r the way nft accepts it: an address, a prefix or lo-hi.
func (r Range) String() string {
	if r.Lo == r.Hi {
		return r.Lo.String()
	}
	for bits := 0; bits <= r.Lo.BitLen(); bits++ {
		p := netip.PrefixFrom(r.Lo, bits)
		if p.Masked().Addr() == r.Lo && PrefixRange(p).Hi == r.Hi {
			return p.String()
		}
	}
	return r.Lo.String() + "-" + r.Hi.String()
}

// Normalize sorts rs and merges overlapping and adjacent ranges. IPv4 sorts
// before IPv6, so the result can be split by family with Split.
func Normalize(rs []Range) []Range {
	rs = slices.Clone(rs)
	slices.SortFunc(rs, func(a, b Range) int { return a.Lo.Compare(b.Lo) })
	var out []Range
	for _, r := range rs {
		if n := len(out); n > 0 && out[n-1].Lo.BitLen() == r.Lo.BitLen() {
			last := &out[n-1]
			next := last.Hi.Next()
			if r.Lo.Compare(last.Hi) <= 0 || (next.IsValid() && next == r.Lo) {
				if r.Hi.Compare(last.Hi) > 0 {
					last.Hi = r.Hi
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// Subtract returns the addresses in rs that are not in cut.
func Subtract(rs, cut []Range) []Range {
	rs, cut = Normalize(rs), Normalize(cut)
	var out []Range
	for _, r := range rs {
		cur, alive := r, true
		for _, c := range cut {
			if !alive || c.Lo.BitLen() != cur.Lo.BitLen() || c.Hi.Less(cur.Lo) || cur.Hi.Less(c.Lo) {
				continue
			}
			if cur.Lo.Less(c.Lo) {
				out = append(out, Range{cur.Lo, c.Lo.Prev()})
			}
			if c.Hi.Less(cur.Hi) {
				cur.Lo = c.Hi.Next()
			} else {
				alive = false
			}
		}
		if alive {
			out = append(out, cur)
		}
	}
	return out
}

// Split separates normalized ranges into IPv4 and IPv6.
func Split(rs []Range) (v4, v6 []Range) {
	for _, r := range rs {
		if r.Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}
	return v4, v6
}
