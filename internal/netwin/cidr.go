package netwin

import (
	"net/netip"
	"sort"
	"strings"
)

// NormalizePrefixes parses IPv4 CIDR ranges, collapses adjacent/overlapping subnets,
// and splits out excludeIP/32 if it falls inside any game subnet so tunnel traffic never loops.
func NormalizePrefixes(ranges []string, excludeIP string) []string {
	var parsed []netip.Prefix
	for _, raw := range ranges {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		parsed = append(parsed, p.Masked())
	}

	collapsed := collapseIPv4(parsed)

	if exAddr, err := netip.ParseAddr(strings.TrimSpace(excludeIP)); err == nil && exAddr.Is4() {
		var split []netip.Prefix
		for _, p := range collapsed {
			if p.Contains(exAddr) {
				split = append(split, excludeAddrFromPrefix(p, exAddr)...)
			} else {
				split = append(split, p)
			}
		}
		collapsed = collapseIPv4(split)
	}

	out := make([]string, len(collapsed))
	for i, p := range collapsed {
		out[i] = p.String()
	}
	return out
}

func InPrefixes(ipStr string, ranges []string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil || !addr.Is4() {
		return false
	}
	for _, r := range ranges {
		s := strings.TrimSpace(r)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

func IsPublicIPv4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return false
	}
	b := addr.As4()
	// Carrier-grade NAT 100.64.0.0/10 & Documentation / Benchmark ranges
	if b[0] == 100 && (b[1]&0xC0) == 64 {
		return false
	}
	if b[0] == 0 || b[0] >= 224 {
		return false
	}
	return true
}

func collapseIPv4(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	cp := make([]netip.Prefix, len(in))
	copy(cp, in)

	sort.Slice(cp, func(i, j int) bool {
		ai, aj := cp[i].Addr().As4(), cp[j].Addr().As4()
		if ai != aj {
			return ipv4ToUint32(ai) < ipv4ToUint32(aj)
		}
		return cp[i].Bits() < cp[j].Bits() // broader prefix first
	})

	// Dropcovered subnets
	var unique []netip.Prefix
	for _, p := range cp {
		if len(unique) > 0 && prefixContainsPrefix(unique[len(unique)-1], p) {
			continue
		}
		unique = append(unique, p)
	}

	// Iteratively merge sibling prefixes (e.g. x.x.0.0/25 + x.x.0.128/25 -> x.x.0.0/24)
	for {
		merged := false
		var next []netip.Prefix
		for i := 0; i < len(unique); i++ {
			if i+1 < len(unique) && unique[i].Bits() == unique[i+1].Bits() && unique[i].Bits() > 0 {
				parentBits := unique[i].Bits() - 1
				parent, _ := unique[i].Addr().Prefix(parentBits)
				parent = parent.Masked()
				if prefixContainsPrefix(parent, unique[i]) && prefixContainsPrefix(parent, unique[i+1]) {
					next = append(next, parent)
					i++
					merged = true
					continue
				}
			}
			next = append(next, unique[i])
		}
		unique = next
		if !merged {
			break
		}
	}
	return unique
}

func excludeAddrFromPrefix(p netip.Prefix, target netip.Addr) []netip.Prefix {
	if !p.Contains(target) {
		return []netip.Prefix{p}
	}
	if p.Bits() == 32 {
		return nil
	}
	var out []netip.Prefix
	cur := p
	tVal := ipv4ToUint32(target.As4())
	for bits := cur.Bits(); bits < 32; bits++ {
		nextBits := bits + 1
		leftAddr := cur.Addr()
		rightVal := ipv4ToUint32(leftAddr.As4()) | (uint32(1) << (32 - nextBits))
		left := netip.PrefixFrom(leftAddr, nextBits)
		right := netip.PrefixFrom(uint32ToIPv4(rightVal), nextBits)

		if (tVal & (uint32(1) << (32 - nextBits))) == 0 {
			out = append(out, right)
			cur = left
		} else {
			out = append(out, left)
			cur = right
		}
	}
	return out
}

func prefixContainsPrefix(outer, inner netip.Prefix) bool {
	if outer.Bits() > inner.Bits() {
		return false
	}
	return outer.Contains(inner.Addr())
}

func ipv4ToUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToIPv4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
