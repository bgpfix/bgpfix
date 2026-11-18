package msg

import (
	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/nlri"
)

// guessAddPath is called after parsing u, with err as the result.
// If it failed, or the first prefix of any NLRI list is /0 (rare in real data, but
// what a small ADD-PATH Path Id reads as without ADD-PATH), and CAP_ADDPATH_GUESS
// is in cps, it checks the unicast NLRI in msg.Data for ADD-PATH Path Identifiers.
// Iff that contradicts msg.HasAddPath(), it parses u again with u.Msg.ParseAddPath
// set to what the data says, and keeps that iff successful. Returns the final result.
func (u *Update) guessAddPath(cps caps.Caps, err error) error {
	if !cps.Has(caps.CAP_ADDPATH_GUESS) {
		return err
	}

	// NB: this must be O(1) for valid messages, so check the first prefixes only
	if err == nil {
		var mpr, mpu []nlri.Prefix
		if mp := u.ReachMP().Prefixes(); mp != nil {
			mpr = mp.Prefixes
		}
		if mp := u.UnreachMP().Prefixes(); mp != nil {
			mpu = mp.Prefixes
		}
		suspect := false
		for _, pfx := range [4][]nlri.Prefix{u.Reach, u.Unreach, mpr, mpu} {
			suspect = suspect || len(pfx) > 0 && pfx[0].Bits() == 0
		}
		if !suspect {
			return err
		}
	}

	// split msg.Data, see Parse
	m := u.Msg
	buf := m.Data
	if len(buf) < UPDATE_MINLEN {
		return err
	}
	l := int(msb.Uint16(buf))
	if 2+l+2 > len(buf) {
		return err
	}
	wdr, buf := buf[2:2+l], buf[2+l:]
	l = int(msb.Uint16(buf))
	if 2+l > len(buf) {
		return err
	}
	ats, reach := buf[2:2+l], buf[2+l:]

	// the new ParseAddPath, for all address families in the message
	var (
		ap      meta.AddPath
		changed bool
		seen    [2]bool // IPv4/IPv6 unicast already checked?
	)

	// check unicast NLRI in src for address family as
	check := func(as afi.AS, src []byte) {
		i := 0
		if as == afi.AS_IPV6_UNICAST {
			i = 1
		}
		if len(src) == 0 || seen[i] {
			return
		}
		seen[i] = true

		// trust the message, unless the data clearly says otherwise
		has := m.HasAddPath(as, cps)
		if !nlri.Check(src, i == 1, has) && nlri.Check(src, i == 1, !has) {
			has = !has
			changed = true
		}
		if has {
			ap.AS = append(ap.AS, as)
		}
	}

	// check IPv4 NLRI, then walk the attributes for MP_*
	check(afi.AS_IPV4_UNICAST, reach)
	check(afi.AS_IPV4_UNICAST, wdr)
	for {
		atyp, val, rest, ok := nextAttr(ats)
		if !ok {
			break
		}
		ats = rest

		code := atyp.Code()
		if (code != attrs.ATTR_MP_REACH && code != attrs.ATTR_MP_UNREACH) || len(val) < 3 {
			continue
		}
		as := afi.NewASBytes(val[0:3])
		switch {
		case as != afi.AS_IPV4_UNICAST && as != afi.AS_IPV6_UNICAST:
			if m.HasAddPath(as, cps) { // not checked, keep as-is
				ap.AS = append(ap.AS, as)
			}
		case code == attrs.ATTR_MP_UNREACH: // afi, safi, nlri
			check(as, val[3:])
		case len(val) >= 4 && len(val) >= 5+int(val[3]): // afi, safi, nh len, nh, reserved, nlri
			check(as, val[5+int(val[3]):])
		}
	}

	if !changed {
		return err
	}

	// retry with the guess, roll back if no better; NB: rare, so allocate
	old := m.ParseAddPath
	m.ParseAddPath = &ap
	if u.parseAll(cps) == nil {
		return nil
	}
	m.ParseAddPath = old
	if err == nil {
		err = u.parseAll(cps)
	}
	return err
}
