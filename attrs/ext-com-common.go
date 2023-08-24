package attrs

import (
	"bytes"
	"net/netip"
	"strconv"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/json"
)

// The basic (raw) Extended Community value
type ExtcomRaw struct {
	uint64
}

func NewExtcomRaw(et ExtcomType) ExtcomValue {
	return &ExtcomRaw{}
}

func (e *ExtcomRaw) Unmarshal(src uint64) error {
	e.uint64 = src
	return nil
}

func (e *ExtcomRaw) Marshal(cps caps.Caps) uint64 {
	return uint64(e.uint64 & 0x0000ffffffffffff)
}

func (e *ExtcomRaw) ToJSON(dst []byte) []byte {
	dst = append(dst, `"0x`...)
	dst = strconv.AppendUint(dst, uint64(e.uint64&0x0000ffffffffffff), 16)
	return append(dst, '"')
}

func (e *ExtcomRaw) FromJSON(src []byte) error {
	v, err := strconv.ParseUint(json.SQ(src), 0, 48)
	if err == nil {
		e.uint64 = v
	}
	return err
}

// 2- or 4-byte ASN-specific value
type ExtcomASN struct {
	et    ExtcomType
	ASN   uint32
	Value uint32
}

func NewExtcomASN(et ExtcomType) ExtcomValue {
	return &ExtcomASN{et: et}
}

func (e *ExtcomASN) Unmarshal(raw uint64) error {
	if e.et.Type()&EXTCOM_AS4 != 0 {
		e.ASN = uint32(raw >> 16)
		e.Value = uint32(raw & 0xffff)
	} else {
		e.ASN = uint32(raw >> 32)
		e.Value = uint32(raw)
	}
	return nil
}

func (e *ExtcomASN) Marshal(cps caps.Caps) uint64 {
	var raw uint64
	if e.et.Type()&EXTCOM_AS4 != 0 {
		raw |= uint64(e.ASN) << 16
		raw |= uint64(e.Value & 0xffff)
	} else {
		raw |= uint64(e.ASN) << 32
		raw |= uint64(e.Value)
	}
	return raw
}

func (e *ExtcomASN) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = strconv.AppendUint(dst, uint64(e.ASN), 10)
	dst = append(dst, ':')
	dst = strconv.AppendUint(dst, uint64(e.Value), 10)
	dst = append(dst, '"')
	return dst
}

func (e *ExtcomASN) FromJSON(src []byte) error {
	d := bytes.Split(json.Q(src), []byte(":"))
	if len(d) != 2 {
		return ErrValue
	}

	v, err := strconv.ParseUint(json.S(d[0]), 10, 32)
	if err != nil {
		return err
	}
	e.ASN = uint32(v)

	v, err = strconv.ParseUint(json.S(d[1]), 10, 32)
	if err != nil {
		return err
	}
	e.Value = uint32(v)

	return nil
}

type ExtcomAddr struct {
	Addr  netip.Addr
	Value uint16
}

func NewExtcomAddr(et ExtcomType) ExtcomValue {
	return &ExtcomAddr{}
}

func (e *ExtcomAddr) Unmarshal(raw uint64) error {
	e.Addr = netip.AddrFrom4([4]byte{
		byte(raw >> 40), byte(raw >> 32),
		byte(raw >> 24), byte(raw >> 16)})
	e.Value = uint16(raw)
	return nil
}

func (e *ExtcomAddr) Marshal(cps caps.Caps) uint64 {
	var raw uint64
	if addr := e.Addr.AsSlice(); len(addr) == 4 {
		raw |= uint64(addr[0]) << 40
		raw |= uint64(addr[1]) << 32
		raw |= uint64(addr[2]) << 24
		raw |= uint64(addr[3]) << 16
	}
	raw |= uint64(e.Value)
	return raw
}

func (e *ExtcomAddr) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = e.Addr.AppendTo(dst)
	dst = append(dst, ':')
	dst = strconv.AppendUint(dst, uint64(e.Value), 10)
	dst = append(dst, '"')
	return dst
}

func (e *ExtcomAddr) FromJSON(src []byte) error {
	d := bytes.Split(json.Q(src), []byte(":"))
	if len(d) != 2 {
		return ErrValue
	}

	a, err := netip.ParseAddr(json.S(d[0]))
	if err != nil {
		return err
	}
	e.Addr = a

	v, err := strconv.ParseUint(json.S(d[1]), 10, 16)
	if err != nil {
		return err
	}
	e.Value = uint16(v)

	return nil
}
