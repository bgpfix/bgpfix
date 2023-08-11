package msg

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"

	jsp "github.com/buger/jsonparser"
)

// AttrRaw represents generic raw attribute
type AttrRaw struct {
	AttrType
	Raw []byte
}

func NewAttrRaw(at AttrType) Attr {
	return &AttrRaw{AttrType: at}
}

func (a *AttrRaw) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) > 0 {
		a.Raw = append(a.Raw, buf...) // copy
	}
	return nil
}

func (a *AttrRaw) Marshal(dst []byte, caps Caps) []byte {
	dst = a.AttrType.MarshalLen(dst, len(a.Raw))
	dst = append(dst, a.Raw...)
	return dst
}

func (a *AttrRaw) ToJSON(dst []byte) []byte {
	if len(a.Raw) > 0 {
		dst = jsonHex(dst, a.Raw)
	} else {
		dst = append(dst, `true`...)
	}
	return dst
}

func (a *AttrRaw) FromJSON(src []byte) (err error) {
	if !bytes.Equal(src, []byte(`true`)) {
		a.Raw, err = unjsonHex(a.Raw[:0], src)
	}
	return
}

// ATTR_ORIGIN
type AttrOrigin struct {
	AttrType
	Origin byte
}

func NewAttrOrigin(at AttrType) Attr {
	return &AttrOrigin{AttrType: at}
}

func (a *AttrOrigin) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) != 1 {
		return ErrLength
	}

	a.Origin = buf[0]
	return nil
}

func (a *AttrOrigin) Marshal(dst []byte, caps Caps) []byte {
	dst = a.AttrType.MarshalLen(dst, 1)
	return append(dst, a.Origin)
}

func (a *AttrOrigin) ToJSON(dst []byte) []byte {
	switch a.Origin {
	case 0:
		return append(dst, `"IGP"`...)
	case 1:
		return append(dst, `"EGP"`...)
	case 2:
		return append(dst, `"INCOMPLETE"`...)
	default:
		return jsonByte(dst, a.Origin)
	}
}

func (a *AttrOrigin) FromJSON(src []byte) (err error) {
	src = unq(src)
	switch bs(src) {
	case "IGP":
		a.Origin = 0
	case "EGP":
		a.Origin = 1
	case "INCOMPLETE":
		a.Origin = 2
	default:
		a.Origin, err = unjsonByte(src)
	}
	return
}

// ATTR_MULTI_EXIT_DISC / ATTR_LOCALPREF
type AttrU32 struct {
	AttrType
	Val uint32
}

func NewAttrU32(at AttrType) Attr {
	return &AttrU32{AttrType: at}
}

func (a *AttrU32) Unmarshal(buf []byte, caps Caps) error {
	if len(buf) != 4 {
		return ErrLength
	}

	a.Val = msb.Uint32(buf)
	return nil
}

func (a *AttrU32) Marshal(dst []byte, caps Caps) []byte {
	dst = a.AttrType.MarshalLen(dst, 4)
	return msb.AppendUint32(dst, a.Val)
}

func (a *AttrU32) ToJSON(dst []byte) []byte {
	return jsonU32(dst, a.Val)
}

func (a *AttrU32) FromJSON(src []byte) (err error) {
	a.Val, err = unjsonU32(src)
	return
}

// ATTR_AGGREGATOR / ATTR_AS4AGGREGATOR
type AttrAggregator struct {
	AttrType
	ASN  uint32
	Addr netip.Addr
}

func NewAttrAggregator(at AttrType) Attr {
	return &AttrAggregator{AttrType: at}
}

func (a *AttrAggregator) Unmarshal(buf []byte, caps Caps) error {
	// asn length
	asnlen := 2
	if a.Code() == ATTR_AS4AGGREGATOR || caps.Has(CAP_AS4) {
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

func (a *AttrAggregator) Marshal(dst []byte, caps Caps) []byte {
	// asn length
	asnlen := 2
	if a.Code() == ATTR_AS4AGGREGATOR || caps.Has(CAP_AS4) {
		asnlen = 4
	}

	dst = a.AttrType.MarshalLen(dst, asnlen+4)
	if asnlen == 4 {
		dst = msb.AppendUint32(dst, a.ASN)
	} else {
		dst = msb.AppendUint16(dst, uint16(a.ASN))
	}
	dst = append(dst, a.Addr.AsSlice()...)

	return dst
}

func (a *AttrAggregator) ToJSON(dst []byte) []byte {
	dst = append(dst, `{"asn":`...)
	dst = strconv.AppendUint(dst, uint64(a.ASN), 10)
	dst = append(dst, `, "addr":"`...)
	dst = a.Addr.AppendTo(dst)
	return append(dst, `"}`...)
}

func (a *AttrAggregator) FromJSON(src []byte) error {
	return jsp.ObjectEach(src, func(key, value []byte, dataType jsp.ValueType, offset int) (err error) {
		switch bs(key) {
		case "asn":
			a.ASN, err = unjsonU32(value)
		case "addr":
			a.Addr, err = netip.ParseAddr(bs(value))
		}
		return
	})
}

// eg. ATTR_NEXTHOP / ATTR_ORIGINATOR
type AttrIP struct {
	AttrType
	IPv6 bool
	Addr netip.Addr
}

func NewAttrIP4(at AttrType) Attr {
	return &AttrIP{AttrType: at}
}

func NewAttrIP6(at AttrType) Attr {
	return &AttrIP{AttrType: at, IPv6: true}
}

func (a *AttrIP) Unmarshal(buf []byte, caps Caps) error {
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

func (a *AttrIP) Marshal(dst []byte, caps Caps) []byte {
	addr := a.Addr.AsSlice()
	dst = a.AttrType.MarshalLen(dst, len(addr))
	dst = append(dst, addr...)
	return dst
}

func (a *AttrIP) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = a.Addr.AppendTo(dst)
	return append(dst, '"')
}

func (a *AttrIP) FromJSON(src []byte) (err error) {
	a.Addr, err = netip.ParseAddr(bsu(src))
	if err != nil {
		return err
	}
	if a.Addr.Is6() != a.IPv6 {
		return ErrValue
	}
	return nil
}

// eg. ATTR_CLUSTER_LIST
type AttrIPList struct {
	AttrType
	IPv6 bool
	Addr []netip.Addr
}

func NewAttrIPList4(at AttrType) Attr {
	return &AttrIPList{AttrType: at}
}

func NewAttrIPList6(at AttrType) Attr {
	return &AttrIPList{AttrType: at, IPv6: true}
}

func (a *AttrIPList) Unmarshal(buf []byte, caps Caps) error {
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

func (a *AttrIPList) Marshal(dst []byte, caps Caps) []byte {
	tl := 0
	for _, addr := range a.Addr {
		if addr.Is6() {
			tl += 16
		} else {
			tl += 4
		}
	}
	dst = a.AttrType.MarshalLen(dst, tl)
	for _, addr := range a.Addr {
		dst = append(dst, addr.AsSlice()...)
	}
	return dst
}

func (a *AttrIPList) ToJSON(dst []byte) []byte {
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

func (a *AttrIPList) FromJSON(src []byte) (reterr error) {
	defer func() {
		if r, ok := recover().(string); ok {
			reterr = fmt.Errorf("%w: %s", ErrValue, r)
		}
	}()

	jsp.ArrayEach(src, func(value []byte, dataType jsp.ValueType, _ int, _ error) {
		addr, err := netip.ParseAddr(bs(value))
		if err != nil {
			panic(err)
		}
		if addr.Is6() != a.IPv6 {
			if a.IPv6 {
				panic("not an IPv6 address")
			} else {
				panic("not an IPv4 address")
			}
		}
		a.Addr = append(a.Addr, addr)
	})

	return
}
