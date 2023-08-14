package attrs

import (
	"net/netip"

	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/json"
	jsp "github.com/buger/jsonparser"
)

// MPPrefixes represents ATTR_MP for the generic RFC4760 IP prefix encoding
type MPPrefixes struct {
	*MP

	NextHop   netip.Addr // only for ATTR_MP_REACH
	LinkLocal netip.Addr // only for IPv6 NextHop, if given
	Prefixes  []netip.Prefix
}

func NewMPPrefixes(mp *MP) MPValue {
	return &MPPrefixes{MP: mp}
}

func (a *MPPrefixes) Unmarshal(cps caps.Caps) error {
	var (
		afi  = a.Afi()
		safi = a.Safi()
		err  error
	)

	// NH defined?
	if len(a.NH) > 0 {
		addr, ll, ok := ParseNH(a.NH)
		if !ok {
			return ErrLength
		}

		if afi == af.AFI_IPV6 {
			a.NextHop = addr
			a.LinkLocal = ll
		} else if addr.Is6() {
			// IPv6 nexthop for AFI=1 reachable prefixes?
			enh, ok := cps.Get(caps.CAP_EXTENDED_NEXTHOP).(*caps.ExtNH)
			if !ok || !enh.Has(afi, safi, af.AFI_IPV6) {
				return ErrValue
			}

			// yes!
			a.NextHop = addr
			a.LinkLocal = ll
		} else {
			a.NextHop = addr
		}
	}

	a.Prefixes, err = ReadPrefixes(a.Prefixes, a.Data, afi == af.AFI_IPV6)
	return err
}

func (a *MPPrefixes) Marshal(cps caps.Caps) {
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
	a.Data = WritePrefixes(a.Data[:0], a.Prefixes)
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
	return json.Prefixes(dst, a.Prefixes)
}

func (a *MPPrefixes) FromJSON(src []byte) error {
	return jsp.ObjectEach(src, func(key, value []byte, dataType jsp.ValueType, offset int) (err error) {
		switch json.BS(key) {
		case "nexthop":
			if a.Code() == ATTR_MP_REACH {
				a.NextHop, err = netip.ParseAddr(json.BS(value))
			}
		case "link-local":
			if a.Code() == ATTR_MP_REACH {
				a.LinkLocal, err = netip.ParseAddr(json.BS(value))
			}
		case "prefixes":
			a.Prefixes, err = json.UnPrefixes(a.Prefixes, value)
		}
		return
	})
}
