package exa

import (
	"encoding/binary"
	"fmt"
	"iter"
	"net/netip"
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/nlri"
)

// ToMsg converts an Exa line r to a bgpfix Msg m.
func (x *Exa) ToMsg(m *msg.Msg) error {
	u := &m.Switch(msg.UPDATE).Update

	if x.Action != "announce" && x.Action != "withdraw" {
		return ErrInvalidAction
	} else if len(x.Flow) > 0 {
		return x.flowToMsg(u)
	} else if len(x.Prefixes) == 0 {
		return ErrInvalidPrefix
	}

	// add the prefixes, all of one address family (ie. one UPDATE)
	var is4 bool
	for i, s := range x.Prefixes {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return ErrInvalidPrefix
		} else if i == 0 {
			is4 = prefix.Addr().Is4()
		} else if prefix.Addr().Is4() != is4 {
			return ErrInvalidPrefix
		}

		if x.Action == "announce" {
			u.AddReach(nlri.FromPrefix(prefix))
		} else {
			u.AddUnreach(nlri.FromPrefix(prefix))
		}
	}

	if x.Action == "announce" {
		return x.writeAttrs(u)
	}
	return nil
}

// writeAttrs creates the BGP attributes from Exa fields
func (x *Exa) writeAttrs(u *msg.Update) error {
	// Next hop is required for announcements
	if x.NextHop != "" && x.NextHop != "self" && len(x.Flow) == 0 {
		addr, err := netip.ParseAddr(x.NextHop)
		if err != nil {
			return ErrInvalidNextHop
		}

		if addr.Is6() {
			mp := u.ReachMP().Prefixes()
			if mp == nil {
				return ErrInvalidNextHop
			}
			mp.NextHop = addr
		} else if mp := u.ReachMP().Prefixes(); mp != nil {
			mp.NextHop = netip.AddrFrom16(addr.As16()) // IPv4-mapped, like ExaBGP
		} else {
			u.Attrs.Use(attrs.ATTR_NEXTHOP).(*attrs.IP).Addr = addr
		}
	}

	// NB: ORIGIN and AS_PATH are mandatory (RFC 4271), a route without them
	// is treated as withdrawn: default to IGP and an empty path, like ExaBGP
	orig := u.Attrs.Use(attrs.ATTR_ORIGIN).(*attrs.Origin)
	switch strings.ToUpper(x.Origin) {
	case "", "IGP":
		orig.Origin = 0
	case "EGP":
		orig.Origin = 1
	case "INCOMPLETE":
		orig.Origin = 2
	default:
		return ErrInvalidOrigin
	}
	u.Attrs.Use(attrs.ATTR_ASPATH).(*attrs.Aspath).Set(x.ASPath)

	// MED
	if x.MED != nil {
		u.Attrs.Use(attrs.ATTR_MED).(*attrs.U32).Val = *x.MED
	}

	// Local preference
	if x.LocalPref != nil {
		u.Attrs.Use(attrs.ATTR_LOCALPREF).(*attrs.U32).Val = *x.LocalPref
	}

	// Communities
	if len(x.Community) > 0 {
		if err := x.writeCommunity(u); err != nil {
			return err
		}
	}

	// Large communities
	for _, c := range x.LargeCommunity {
		var v [3]uint64
		parts := strings.Split(c, ":")
		if len(parts) != 3 {
			return ErrInvalidCommunity
		}
		for i := range parts {
			var err error
			if v[i], err = strconv.ParseUint(parts[i], 10, 32); err != nil {
				return ErrInvalidCommunity
			}
		}
		u.Attrs.Use(attrs.ATTR_LARGE_COMMUNITY).(*attrs.LargeCom).Add(uint32(v[0]), uint32(v[1]), uint32(v[2]))
	}

	// Extended communities
	for _, c := range x.ExtCommunity {
		v, err := parseExtcom(c)
		if err != nil {
			return err
		}
		ec := u.Attrs.Use(attrs.ATTR_EXT_COMMUNITY).(*attrs.Extcom)
		if err := ec.Unmarshal(binary.BigEndian.AppendUint64(nil, v), caps.Caps{}, meta.Meta{}); err != nil {
			return ErrInvalidCommunity
		}
	}

	// Aggregation
	if x.AtomicAggregate {
		u.Attrs.Use(attrs.ATTR_AGGREGATE)
	}
	if x.Aggregator != "" {
		as, ip, _ := strings.Cut(x.Aggregator, ":")
		asn, err1 := strconv.ParseUint(as, 10, 32)
		addr, err2 := netip.ParseAddr(ip)
		if err1 != nil || err2 != nil || !addr.Is4() {
			return ErrInvalidValue
		}
		agg := u.Attrs.Use(attrs.ATTR_AGGREGATOR).(*attrs.Aggregator)
		agg.ASN, agg.Addr = uint32(asn), addr
	}

	// Route reflection
	if x.OriginatorID != "" {
		addr, err := netip.ParseAddr(x.OriginatorID)
		if err != nil || !addr.Is4() {
			return ErrInvalidValue
		}
		u.Attrs.Use(attrs.ATTR_ORIGINATOR).(*attrs.IP).Addr = addr
	}
	for _, c := range x.ClusterList {
		addr, err := netip.ParseAddr(c)
		if err != nil || !addr.Is4() {
			return ErrInvalidValue
		}
		cl := u.Attrs.Use(attrs.ATTR_CLUSTER_LIST).(*attrs.IPList)
		cl.Addr = append(cl.Addr, addr)
	}

	return nil
}

// parseExtcom parses an extended community in ExaBGP format:
// target:<asn|ip>:<number>, origin:<asn|ip>:<number>, or 0x<16 hex digits>
func parseExtcom(s string) (uint64, error) {
	if len(s) == 18 && strings.HasPrefix(s, "0x") {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return 0, ErrInvalidCommunity
		}
		return v, nil
	}

	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return 0, ErrInvalidCommunity
	}

	var typ uint64
	switch parts[0] {
	case "target":
		typ = uint64(attrs.EXTCOM_TARGET)
	case "origin":
		typ = uint64(attrs.EXTCOM_ORIGIN)
	default:
		return 0, ErrInvalidCommunity
	}

	// global administrator: IPv4 address, 2-byte ASN, or 4-byte ASN
	var val uint64
	nbits := 16 // local administrator size
	if addr, err := netip.ParseAddr(parts[1]); err == nil && addr.Is4() {
		typ |= uint64(attrs.EXTCOM_IP4)
		val = uint64(binary.BigEndian.Uint32(addr.AsSlice())) << 16
	} else if asn, err := strconv.ParseUint(parts[1], 10, 32); err != nil {
		return 0, ErrInvalidCommunity
	} else if asn > 0xffff {
		typ |= uint64(attrs.EXTCOM_AS4)
		val = asn << 16
	} else {
		val = asn << 32
		nbits = 32
	}

	num, err := strconv.ParseUint(parts[2], 10, nbits)
	if err != nil {
		return 0, ErrInvalidCommunity
	}
	return typ<<48 | val | num, nil
}

// formatExtcom is the reverse of parseExtcom
func formatExtcom(v uint64) string {
	name := ""
	switch attrs.ExtcomType(v >> 48).Subtype() {
	case attrs.EXTCOM_TARGET:
		name = "target"
	case attrs.EXTCOM_ORIGIN:
		name = "origin"
	}

	if name != "" {
		switch attrs.ExtcomType(v>>48) & 0xff00 { // NB: transitive only
		case attrs.EXTCOM_AS2:
			return fmt.Sprintf("%s:%d:%d", name, uint16(v>>32), uint32(v))
		case attrs.EXTCOM_AS4:
			return fmt.Sprintf("%s:%d:%d", name, uint32(v>>16), uint16(v))
		case attrs.EXTCOM_IP4:
			ip := netip.AddrFrom4([4]byte{byte(v >> 40), byte(v >> 32), byte(v >> 24), byte(v >> 16)})
			return fmt.Sprintf("%s:%s:%d", name, ip, uint16(v))
		}
	}
	return fmt.Sprintf("0x%016x", v)
}

// writeCommunity creates the COMMUNITY attribute using the bgpipe pattern
func (x *Exa) writeCommunity(u *msg.Update) error {
	comm := u.Attrs.Use(attrs.ATTR_COMMUNITY).(*attrs.Community)

	for _, c := range x.Community {
		switch c {
		case "no-export":
			comm.Add(0xFFFF, 0xFF01)
		case "no-advertise":
			comm.Add(0xFFFF, 0xFF02)
		case "no-export-subconfed":
			comm.Add(0xFFFF, 0xFF03)
		case "no-peer":
			comm.Add(0xFFFF, 0xFF04)
		case "blackhole":
			comm.Add(0xFFFF, 0x029A)
		default:
			// Parse AS:value format
			parts := strings.Split(c, ":")
			if len(parts) == 2 {
				as, err1 := strconv.ParseUint(parts[0], 0, 16)
				val, err2 := strconv.ParseUint(parts[1], 0, 16)
				if err1 == nil && err2 == nil {
					comm.Add(uint16(as), uint16(val))
				} else {
					return ErrInvalidCommunity
				}
			} else {
				return ErrInvalidCommunity
			}
		}
	}

	return nil
}

// IterMsg returns an iterator that converts bgpfix Msg (UPDATE) to Exa lines:
// it returns x updated with all reachable prefixes, then with all unreachable prefixes.
func (x *Exa) IterMsg(m *msg.Msg) iter.Seq[*Exa] {
	return func(yield func(*Exa) bool) {
		if m == nil || m.Type != msg.UPDATE {
			return
		}
		u := &m.Update

		// NB: IPv4 in the UPDATE and another family in MP_* are separate lines,
		// each with its own next-hop
		reach, unreach := u.ReachMP().Prefixes(), u.UnreachMP().Prefixes()
		each := func(action string, prefixes []nlri.Prefix, nh netip.Addr) bool {
			if len(prefixes) == 0 {
				return true
			}
			x.Reset()
			x.Action = action
			if action == "announce" {
				x.readMsgAttrs(u)
				x.NextHop = ""
				if nh.IsValid() && !nh.IsUnspecified() {
					x.NextHop = nh.String()
				}
			}
			for _, prefix := range prefixes {
				x.Prefixes = append(x.Prefixes, prefix.String())
			}
			return yield(x)
		}

		var nh4 netip.Addr
		if nh, ok := u.Attrs.Get(attrs.ATTR_NEXTHOP).(*attrs.IP); ok {
			nh4 = nh.Addr
		}
		if !each("announce", u.Reach, nh4) {
			return
		}
		if reach != nil && !each("announce", reach.Prefixes, reach.NextHop) {
			return
		}
		if !each("withdraw", u.Unreach, nh4) {
			return
		}
		if unreach != nil && !each("withdraw", unreach.Prefixes, nh4) {
			return
		}

		// Handle Flowspec: a line per rule
		for _, code := range []attrs.Code{attrs.ATTR_MP_REACH, attrs.ATTR_MP_UNREACH} {
			mp, _ := u.Attrs.Get(code).(*attrs.MP)
			if mp == nil {
				continue
			}
			fs, _ := mp.Value.(*attrs.MPFlowspec)
			if fs == nil {
				continue
			}
			for _, rule := range fs.Rules {
				x.Reset()
				x.Action = "withdraw"
				if code == attrs.ATTR_MP_REACH {
					x.Action = "announce"
					x.readMsgAttrs(u)
					if fs.NextHop.IsValid() {
						x.NextHop = fs.NextHop.String()
					}
				}
				v6 := 0
				if mp.Afi() == afi.AFI_IPV6 {
					v6 = 1
				}
				if x.readFlow(rule, v6) && len(x.Flow) > 0 && !yield(x) {
					return
				}
			}
		}
	}
}

// readMsgAttrs extracts BGP attributes from UPDATE into Exa
func (x *Exa) readMsgAttrs(u *msg.Update) {
	// no attributes defined?
	if u.Attrs.Len() == 0 {
		return
	}

	// Origin
	if orig, ok := u.Attrs.Get(attrs.ATTR_ORIGIN).(*attrs.Origin); ok {
		switch orig.Origin {
		case 0:
			x.Origin = "IGP"
		case 1:
			x.Origin = "EGP"
		case 2:
			x.Origin = "INCOMPLETE"
		}
	}

	// AS path
	if aspath, ok := u.Attrs.Get(attrs.ATTR_ASPATH).(*attrs.Aspath); ok && aspath.IsValid() {
		var asns []uint32
		for _, seg := range aspath.Segments {
			asns = append(asns, seg.List...)
		}
		x.ASPath = asns
	}

	// MED
	if med, ok := u.Attrs.Get(attrs.ATTR_MED).(*attrs.U32); ok {
		x.MED = &med.Val
	}

	// Local preference
	if lp, ok := u.Attrs.Get(attrs.ATTR_LOCALPREF).(*attrs.U32); ok {
		x.LocalPref = &lp.Val
	}

	// Communities
	if comm, ok := u.Attrs.Get(attrs.ATTR_COMMUNITY).(*attrs.Community); ok && comm.Len() > 0 {
		var communities []string

		for i := 0; i < comm.Len(); i++ {
			as := comm.ASN[i]
			val := comm.Value[i]
			if as == 0xFFFF {
				switch val {
				case 0xFF01:
					communities = append(communities, "no-export")
				case 0xFF02:
					communities = append(communities, "no-advertise")
				case 0xFF03:
					communities = append(communities, "no-export-subconfed")
				case 0xFF04:
					communities = append(communities, "no-peer")
				case 0x029A:
					communities = append(communities, "blackhole")
				default:
					communities = append(communities, fmt.Sprintf("%d:%d", as, val))
				}
			} else {
				communities = append(communities, fmt.Sprintf("%d:%d", as, val))
			}
		}

		x.Community = communities
	}

	// Extended communities
	if ec, ok := u.Attrs.Get(attrs.ATTR_EXT_COMMUNITY).(*attrs.Extcom); ok {
		for i, val := range ec.Value {
			if val != nil {
				v := uint64(ec.Type[i])<<48 | val.Marshal()&0xffffffffffff
				x.ExtCommunity = append(x.ExtCommunity, formatExtcom(v))
			}
		}
	}

	// Aggregation
	x.AtomicAggregate = u.Attrs.Has(attrs.ATTR_AGGREGATE)
	if agg, ok := u.Attrs.Get(attrs.ATTR_AGGREGATOR).(*attrs.Aggregator); ok && agg.Addr.IsValid() {
		x.Aggregator = fmt.Sprintf("%d:%s", agg.ASN, agg.Addr)
	}

	// Route reflection
	if id, ok := u.Attrs.Get(attrs.ATTR_ORIGINATOR).(*attrs.IP); ok && id.Addr.IsValid() {
		x.OriginatorID = id.Addr.String()
	}
	if cl, ok := u.Attrs.Get(attrs.ATTR_CLUSTER_LIST).(*attrs.IPList); ok {
		for _, addr := range cl.Addr {
			x.ClusterList = append(x.ClusterList, addr.String())
		}
	}

	// Large communities
	if lc, ok := u.Attrs.Get(attrs.ATTR_LARGE_COMMUNITY).(*attrs.LargeCom); ok {
		for i := range lc.ASN {
			x.LargeCommunity = append(x.LargeCommunity, fmt.Sprintf("%d:%d:%d", lc.ASN[i], lc.Value1[i], lc.Value2[i]))
		}
	}
}
