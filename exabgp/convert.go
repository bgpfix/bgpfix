package exabgp

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

// ToMsg converts a Line to a bgpfix Msg m.
func (r *Line) ToMsg(m *msg.Msg) error {
	u := &m.Use(msg.UPDATE).Update

	// Parse the prefix
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return ErrInvalidPrefix
	}
	pfx := nlri.FromPrefix(prefix)

	// Set up the message based on action
	switch r.Action {
	case "announce":
		if err := r.writeAttrs(u); err != nil {
			return err
		}
		u.AddReach(pfx)
	case "withdraw":
		u.AddUnreach(pfx)
	default:
		return ErrInvalidAction
	}

	return nil
}

// writeAttrs creates the BGP attributes from Line fields
func (r *Line) writeAttrs(u *msg.Update) error {
	// Next hop is required for announcements
	if r.NextHop != "" {
		if r.NextHop == "self" {
			return ErrNextHopSelf
		}

		addr, err := netip.ParseAddr(r.NextHop)
		if err != nil {
			return ErrInvalidNextHop
		}

		u.Attrs.Use(attrs.ATTR_NEXTHOP).(*attrs.IP).Addr = addr
	}

	// Origin attribute
	if r.Origin != "" {
		orig := u.Attrs.Use(attrs.ATTR_ORIGIN).(*attrs.Origin)
		switch strings.ToUpper(r.Origin) {
		case "IGP":
			orig.Origin = 0
		case "EGP":
			orig.Origin = 1
		case "INCOMPLETE":
			orig.Origin = 2
		default:
			return ErrInvalidOrigin
		}
	}

	// AS path
	if len(r.ASPath) > 0 {
		u.Attrs.Use(attrs.ATTR_ASPATH).(*attrs.Aspath).Set(r.ASPath)
	}

	// MED
	if r.MED != nil {
		u.Attrs.Use(attrs.ATTR_MED).(*attrs.U32).Val = *r.MED
	}

	// Local preference
	if r.LocalPref != nil {
		u.Attrs.Use(attrs.ATTR_LOCALPREF).(*attrs.U32).Val = *r.LocalPref
	}

	// Communities
	if len(r.Community) > 0 {
		if err := r.writeCommunity(u); err != nil {
			return err
		}
	}

	return nil
}

// writeCommunity creates the COMMUNITY attribute using the bgpipe pattern
func (r *Line) writeCommunity(u *msg.Update) error {
	comm := u.Attrs.Use(attrs.ATTR_COMMUNITY).(*attrs.Community)

	for _, c := range r.Community {
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

// FromMsg returns an iterator that converts bgpfix Msg (UPDATE) to Lines.
// For each reachable and unreachable prefix, it yields a Line.
// The iterator updates the Line r for each prefix.
func (r *Line) FromMsg(m *msg.Msg) iter.Seq[*Line] {
	return func(yield func(*Line) bool) {
		if m == nil || m.Type != msg.UPDATE {
			return
		}
		u := &m.Update

		// Handle announcements (reachable prefixes)
		if u.HasReach() {
			r.Reset()
			r.Action = "announce"
			r.readMsgAttrs(u)
			for _, prefix := range u.AllReach() {
				r.Prefix = prefix.String()
				if !yield(r) {
					return
				}
			}
		}

		// Handle withdrawals (unreachable prefixes)
		if u.HasUnreach() {
			r.Reset()
			r.Action = "withdraw"
			for _, prefix := range u.AllUnreach() {
				r.Prefix = prefix.String()
				if !yield(r) {
					return
				}
			}
		}
	}
}

// readMsgAttrs extracts BGP attributes from UPDATE into Line
func (r *Line) readMsgAttrs(u *msg.Update) {
	// no attributes defined?
	if u.Attrs.Len() == 0 {
		return
	}

	// Next hop
	nh := u.NextHop()
	if nh.IsValid() {
		r.NextHop = nh.String()
	}

	// Origin
	if orig, ok := u.Attrs.Get(attrs.ATTR_ORIGIN).(*attrs.Origin); ok {
		switch orig.Origin {
		case 0:
			r.Origin = "IGP"
		case 1:
			r.Origin = "EGP"
		case 2:
			r.Origin = "INCOMPLETE"
		}
	}

	// AS path
	aspath := u.AsPath()
	if aspath != nil && aspath.Valid() {
		var asns []uint32
		for _, seg := range aspath.Segments {
			asns = append(asns, seg.List...)
		}
		r.ASPath = asns
	}

	// MED
	if med, ok := u.Attrs.Get(attrs.ATTR_MED).(*attrs.U32); ok {
		r.MED = &med.Val
	}

	// Local preference
	if lp, ok := u.Attrs.Get(attrs.ATTR_LOCALPREF).(*attrs.U32); ok {
		r.LocalPref = &lp.Val
	}

	// Communities
	comm := u.Community()
	if comm != nil && comm.Len() > 0 {
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

		r.Community = communities
	}
}
