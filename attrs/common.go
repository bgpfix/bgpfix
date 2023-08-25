package attrs

import (
	"bytes"
	"net/netip"
	"strconv"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/json"
)

// Raw represents generic raw attribute
type Raw struct {
	CodeFlags
	Raw []byte
}

func NewRaw(at CodeFlags) Attr {
	return &Raw{CodeFlags: at}
}

func (a *Raw) Unmarshal(buf []byte, cps caps.Caps) error {
	if len(buf) > 0 {
		a.Raw = append(a.Raw, buf...) // copy
	}
	return nil
}

func (a *Raw) Marshal(dst []byte, cps caps.Caps) []byte {
	dst = a.CodeFlags.MarshalLen(dst, len(a.Raw))
	dst = append(dst, a.Raw...)
	return dst
}

func (a *Raw) ToJSON(dst []byte) []byte {
	if len(a.Raw) > 0 {
		dst = json.Hex(dst, a.Raw)
	} else {
		dst = append(dst, json.True...)
	}
	return dst
}

func (a *Raw) FromJSON(src []byte) (err error) {
	if !bytes.Equal(src, json.True) {
		a.Raw, err = json.UnHex(src, a.Raw[:0])
	}
	return
}

// Origin represents ATTR_ORIGIN
type Origin struct {
	CodeFlags
	Origin byte
}

func NewOrigin(at CodeFlags) Attr {
	return &Origin{CodeFlags: at}
}

func (a *Origin) Unmarshal(buf []byte, cps caps.Caps) error {
	if len(buf) != 1 {
		return ErrLength
	}

	a.Origin = buf[0]
	return nil
}

func (a *Origin) Marshal(dst []byte, cps caps.Caps) []byte {
	dst = a.CodeFlags.MarshalLen(dst, 1)
	return append(dst, a.Origin)
}

func (a *Origin) ToJSON(dst []byte) []byte {
	switch a.Origin {
	case 0:
		return append(dst, `"IGP"`...)
	case 1:
		return append(dst, `"EGP"`...)
	case 2:
		return append(dst, `"INCOMPLETE"`...)
	default:
		return json.Byte(dst, a.Origin)
	}
}

func (a *Origin) FromJSON(src []byte) (err error) {
	src = json.Q(src)
	switch json.S(src) {
	case "IGP":
		a.Origin = 0
	case "EGP":
		a.Origin = 1
	case "INCOMPLETE":
		a.Origin = 2
	default:
		a.Origin, err = json.UnByte(src)
	}
	return
}

// U32 represents uint32 valued attributes, eg. ATTR_MULTI_EXIT_DISC / ATTR_LOCALPREF
type U32 struct {
	CodeFlags
	Val uint32
}

func NewU32(at CodeFlags) Attr {
	return &U32{CodeFlags: at}
}

func (a *U32) Unmarshal(buf []byte, cps caps.Caps) error {
	if len(buf) != 4 {
		return ErrLength
	}

	a.Val = msb.Uint32(buf)
	return nil
}

func (a *U32) Marshal(dst []byte, cps caps.Caps) []byte {
	dst = a.CodeFlags.MarshalLen(dst, 4)
	return msb.AppendUint32(dst, a.Val)
}

func (a *U32) ToJSON(dst []byte) []byte {
	return json.Uint32(dst, a.Val)
}

func (a *U32) FromJSON(src []byte) (err error) {
	a.Val, err = json.UnUint32(src)
	return
}

// Aggregator represents ATTR_AGGREGATOR / ATTR_AS4AGGREGATOR
type Aggregator struct {
	CodeFlags
	ASN  uint32
	Addr netip.Addr
}

func NewAggregator(at CodeFlags) Attr {
	return &Aggregator{CodeFlags: at}
}

func (a *Aggregator) Unmarshal(buf []byte, cps caps.Caps) error {
	// asn length
	asnlen := 2
	if a.Code() == ATTR_AS4AGGREGATOR || cps.Has(caps.CAP_AS4) {
		asnlen = 4
	}

	if len(buf) != asnlen+4 {
		return ErrLength
	}

	if asnlen == 4 {
		a.ASN = msb.Uint32(buf)
		buf = buf[4:8]
	} else {
		a.ASN = uint32(msb.Uint16(buf))
		buf = buf[2:6]
	}
	a.Addr = netip.AddrFrom4([4]byte(buf))

	return nil
}

func (a *Aggregator) Marshal(dst []byte, cps caps.Caps) []byte {
	// asn length
	asnlen := 2
	if a.Code() == ATTR_AS4AGGREGATOR || cps.Has(caps.CAP_AS4) {
		asnlen = 4
	}

	dst = a.CodeFlags.MarshalLen(dst, asnlen+4)
	if asnlen == 4 {
		dst = msb.AppendUint32(dst, a.ASN)
	} else {
		dst = msb.AppendUint16(dst, uint16(a.ASN))
	}
	dst = append(dst, a.Addr.AsSlice()...)

	return dst
}

func (a *Aggregator) ToJSON(dst []byte) []byte {
	dst = append(dst, `{"asn":`...)
	dst = strconv.AppendUint(dst, uint64(a.ASN), 10)
	dst = append(dst, `, "addr":"`...)
	dst = a.Addr.AppendTo(dst)
	return append(dst, `"}`...)
}

func (a *Aggregator) FromJSON(src []byte) error {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) (err error) {
		switch key {
		case "asn":
			a.ASN, err = json.UnUint32(val)
		case "addr":
			a.Addr, err = netip.ParseAddr(json.S(val))
		}
		return
	})
}

// IP represents IP address attributes, eg. ATTR_NEXTHOP / ATTR_ORIGINATOR
type IP struct {
	CodeFlags
	IPv6 bool
	Addr netip.Addr
}

func NewIP4(at CodeFlags) Attr {
	return &IP{CodeFlags: at}
}

func NewIP6(at CodeFlags) Attr {
	return &IP{CodeFlags: at, IPv6: true}
}

func (a *IP) Unmarshal(buf []byte, cps caps.Caps) error {
	switch {
	case !a.IPv6 && len(buf) == 4:
		a.Addr = netip.AddrFrom4([4]byte(buf))
	case a.IPv6 && len(buf) == 16:
		a.Addr = netip.AddrFrom16([16]byte(buf))
	default:
		return ErrLength
	}
	return nil
}

func (a *IP) Marshal(dst []byte, cps caps.Caps) []byte {
	addr := a.Addr.AsSlice()
	dst = a.CodeFlags.MarshalLen(dst, len(addr))
	dst = append(dst, addr...)
	return dst
}

func (a *IP) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = a.Addr.AppendTo(dst)
	return append(dst, '"')
}

func (a *IP) FromJSON(src []byte) (err error) {
	a.Addr, err = netip.ParseAddr(json.SQ(src))
	if err != nil {
		return err
	}
	if a.Addr.Is6() != a.IPv6 {
		return ErrValue
	}
	return nil
}

// IPList represents IP prefix list attributes, eg. ATTR_CLUSTER_LIST
type IPList struct {
	CodeFlags
	IPv6 bool
	Addr []netip.Addr
}

func NewIPList4(at CodeFlags) Attr {
	return &IPList{CodeFlags: at}
}

func NewIPList6(at CodeFlags) Attr {
	return &IPList{CodeFlags: at, IPv6: true}
}

func (a *IPList) Unmarshal(buf []byte, cps caps.Caps) error {
	var addr netip.Addr
	for len(buf) > 0 {
		if a.IPv6 {
			if len(buf) < 16 {
				return ErrLength
			}
			addr = netip.AddrFrom16([16]byte(buf[:16]))
			buf = buf[16:]
		} else {
			if len(buf) < 4 {
				return ErrLength
			}
			addr = netip.AddrFrom4([4]byte(buf[:4]))
			buf = buf[4:]
		}

		a.Addr = append(a.Addr, addr)
	}

	return nil
}

func (a *IPList) Marshal(dst []byte, cps caps.Caps) []byte {
	tl := 0
	for _, addr := range a.Addr {
		if addr.Is6() {
			tl += 16
		} else {
			tl += 4
		}
	}
	dst = a.CodeFlags.MarshalLen(dst, tl)
	for _, addr := range a.Addr {
		dst = append(dst, addr.AsSlice()...)
	}
	return dst
}

func (a *IPList) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i := range a.Addr {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, '"')
		dst = a.Addr[i].AppendTo(dst)
		dst = append(dst, '"')
	}
	return append(dst, ']')
}

func (a *IPList) FromJSON(src []byte) (reterr error) {
	return json.ArrayEach(src, func(key int, val []byte, typ json.Type) error {
		addr, err := netip.ParseAddr(json.S(val))
		if err != nil {
			return err
		}
		if addr.Is6() != a.IPv6 {
			return ErrAF
		}
		a.Addr = append(a.Addr, addr)
		return nil
	})

	return
}
