package attrs

import (
	"net/netip"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/nlri"
)

// MPPrefixes represents ATTR_MP for the generic RFC4760 IP prefix encoding
type MPPrefixes struct {
	*MP

	NextHop   netip.Addr // only for ATTR_MP_REACH
	LinkLocal netip.Addr // only for IPv6 NextHop, if given
	Prefixes  []nlri.NLRI
}

func NewMPPrefixes(mp *MP) MPValue {
	return &MPPrefixes{MP: mp}
}

func (a *MPPrefixes) Reset() {
	a.NextHop = netip.Addr{}
	a.LinkLocal = netip.Addr{}
	a.Prefixes = a.Prefixes[:0]
}

// Len returns the number of prefixes in a, if non-nil
func (a *MPPrefixes) Len() int {
	if a == nil {
		return 0
	} else {
		return len(a.Prefixes)
	}
}

func (a *MPPrefixes) Unmarshal(cps caps.Caps, dir dir.Dir) error {
	var (
		isv6 = a.IsIPv6()
		err  error
	)

	// NH defined?
	if len(a.NH) > 0 {
		addr, ll, ok := ParseNH(a.NH)
		if !ok {
			return ErrLength
		}

		if isv6 {
			a.NextHop = addr
			a.LinkLocal = ll
		} else if addr.Is6() {
			// IPv6 nexthop for AFI=1 reachable prefixes?
			enh, ok := cps.Get(caps.CAP_EXTENDED_NEXTHOP).(*caps.ExtNH)
			if !ok || !enh.Has(a.AS, afi.AFI_IPV6) {
				return ErrValue
			}

			// yes!
			a.NextHop = addr
			a.LinkLocal = ll
		} else {
			a.NextHop = addr
		}
	}

	a.Prefixes, err = nlri.Unmarshal(a.Prefixes, a.Data, a.AS, cps, dir)
	return err
}

func (a *MPPrefixes) Marshal(cps caps.Caps, dir dir.Dir) {
	// next-hop
	nh := a.NH[:0]
	if a.NextHop.IsValid() {
		nh = append(nh, a.NextHop.AsSlice()...)
		if a.LinkLocal.IsValid() {
			nh = append(nh, a.LinkLocal.AsSlice()...)
		}
	}
	a.NH = nh

	// prefixes
	a.Data = nlri.Marshal(a.Data[:0], a.Prefixes, a.AS, cps, dir)
}

func (a *MPPrefixes) ToJSON(dst []byte) []byte {
	if a.Code() == ATTR_MP_REACH {
		dst = append(dst, `"nexthop":"`...)
		dst = a.NextHop.AppendTo(dst)
		if a.LinkLocal.IsValid() {
			dst = append(dst, `","link-local":"`...)
			dst = a.LinkLocal.AppendTo(dst)
		}
		dst = append(dst, `",`...)
	}

	dst = append(dst, `"prefixes":`...)
	return nlri.ToJSON(dst, a.Prefixes)
}

func (a *MPPrefixes) FromJSON(src []byte) error {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) (err error) {
		switch key {
		case "nexthop":
			if a.Code() == ATTR_MP_REACH {
				a.NextHop, err = netip.ParseAddr(json.S(val))
			}
		case "link-local":
			if a.Code() == ATTR_MP_REACH {
				a.LinkLocal, err = netip.ParseAddr(json.S(val))
			}
		case "prefixes":
			a.Prefixes, err = nlri.FromJSON(val, a.Prefixes)
		}
		return err
	})
}
