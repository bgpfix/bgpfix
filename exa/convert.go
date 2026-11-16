package exa

import (
	"fmt"
	"iter"
	"net/netip"
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/nlri"
)

// ToMsg converts an Exa line r to a bgpfix Msg m.
func (x *Exa) ToMsg(m *msg.Msg) error {
	u := &m.Switch(msg.UPDATE).Update

	// Parse the prefix
	prefix, err := netip.ParsePrefix(x.Prefix)
	if err != nil {
		return ErrInvalidPrefix
	}
	pfx := nlri.FromPrefix(prefix)

	// Set up the message based on action
	switch x.Action {
	case "announce":
		u.AddReach(pfx)
		if err := x.writeAttrs(u); err != nil {
			return err
		}
	case "withdraw":
		u.AddUnreach(pfx)
	default:
		return ErrInvalidAction
	}

	return nil
}

// writeAttrs creates the BGP attributes from Exa fields
func (x *Exa) writeAttrs(u *msg.Update) error {
	// Next hop is required for announcements
	if x.NextHop != "" && x.NextHop != "self" {
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

	return nil
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

// IterMsg returns an iterator that converts bgpfix Msg (UPDATE) to Exa lines.
// For each reachable and unreachable prefix, it returns x after updating it.
func (x *Exa) IterMsg(m *msg.Msg) iter.Seq[*Exa] {
	return func(yield func(*Exa) bool) {
		if m == nil || m.Type != msg.UPDATE {
			return
		}
		u := &m.Update

		// Handle announcements (reachable prefixes)
		if u.HasReach() {
			x.Reset()
			x.Action = "announce"
			x.readMsgAttrs(u)
			for _, prefix := range u.AllReach() {
				x.Str = "" // force update
				x.Prefix = prefix.String()
				if !yield(x) {
					return
				}
			}
		}

		// Handle withdrawals (unreachable prefixes)
		if u.HasUnreach() {
			x.Reset()
			x.Action = "withdraw"
			for _, prefix := range u.AllUnreach() {
				x.Str = "" // force update
				x.Prefix = prefix.String()
				if !yield(x) {
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

	// Next hop - directly check from attributes since we know they're available
	if nh, ok := u.Attrs.Get(attrs.ATTR_NEXTHOP).(*attrs.IP); ok {
		if nh.Addr.IsValid() && !nh.Addr.IsUnspecified() {
			x.NextHop = nh.Addr.String()
		}
	} else if mp := u.ReachMP().Prefixes(); mp != nil {
		if mp.NextHop.IsValid() && !mp.NextHop.IsUnspecified() {
			x.NextHop = mp.NextHop.String()
		}
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

	// Large communities
	if lc, ok := u.Attrs.Get(attrs.ATTR_LARGE_COMMUNITY).(*attrs.LargeCom); ok {
		for i := range lc.ASN {
			x.LargeCommunity = append(x.LargeCommunity, fmt.Sprintf("%d:%d:%d", lc.ASN[i], lc.Value1[i], lc.Value2[i]))
		}
	}
}
