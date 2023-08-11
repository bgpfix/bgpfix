package msg

import (
	"net/netip"

	jsp "github.com/buger/jsonparser"
)

// ATTR_MP_* for the generic RFC4760 IP prefix encoding
type AttrMPPrefixes struct {
	*AttrMP

	NextHop   netip.Addr // only for ATTR_MP_REACH
	LinkLocal netip.Addr // only for IPv6 NextHop, if given
	Prefixes  []netip.Prefix
}

func NewAttrMPPrefixes(mp *AttrMP) AttrMPValue {
	return &AttrMPPrefixes{AttrMP: mp}
}

func (a *AttrMPPrefixes) Unmarshal(caps Caps) error {
	var (
		afi  = a.Afi()
		safi = a.Safi()
		err  error
	)

	// NH defined?
	if len(a.NH) > 0 {
		addr, ll, ok := parseNH(a.NH)
		if !ok {
			return ErrLength
		}

		if afi == AFI_IPV6 {
			a.NextHop = addr
			a.LinkLocal = ll
		} else if addr.Is6() {
			// IPv6 nexthop for AFI=1 reachable prefixes?
			enh, ok := caps.Get(CAP_EXTENDED_NEXTHOP).(*CapExtNH)
			if !ok || !enh.Has(afi, safi, AFI_IPV6) {
				return ErrValue
			}

			// yes!
			a.NextHop = addr
			a.LinkLocal = ll
		} else {
			a.NextHop = addr
		}
	}

	a.Prefixes, err = appendPrefixes(a.Prefixes, a.Data, afi == AFI_IPV6)
	return err
}

func (a *AttrMPPrefixes) Marshal(caps Caps) {
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
	a.Data = marshalPrefixes(a.Data[:0], a.Prefixes)
}

func (a *AttrMPPrefixes) ToJSON(dst []byte) []byte {
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
	return jsonPrefixes(dst, a.Prefixes)
}

func (a *AttrMPPrefixes) FromJSON(src []byte) error {
	return jsp.ObjectEach(src, func(key, value []byte, dataType jsp.ValueType, offset int) (err error) {
		switch bs(key) {
		case "nexthop":
			if a.Code() == ATTR_MP_REACH {
				a.NextHop, err = netip.ParseAddr(bs(value))
			}
		case "link-local":
			if a.Code() == ATTR_MP_REACH {
				a.LinkLocal, err = netip.ParseAddr(bs(value))
			}
		case "prefixes":
			a.Prefixes, err = unjsonPrefixes(a.Prefixes, value)
		}
		return
	})
}
