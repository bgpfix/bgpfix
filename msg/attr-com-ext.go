package msg

import (
	"bytes"
	"fmt"
	"math"
	"net/netip"
	"strconv"

	jsp "github.com/buger/jsonparser"
)

// ATTR_EXT_COMMUNITY
type AttrExtCom struct {
	AttrType

	Type  []ExcomType  // top 2 bytes (always the "Extended" type)
	Value []ExcomValue // bottom 6 bytes
}

// Extended Community Type
type ExcomType uint16

// Extended Community Value
type ExcomValue interface {
	// Unmarshal NewExcoms wire representation from src
	Unmarshal(src uint64) error

	// Marshal returns wire representation of the value
	Marshal(caps Caps) uint64

	// ToJSON appends JSON representation of the value to dst
	ToJSON(dst []byte) []byte

	// FromJSON reads value from JSON representation in src
	FromJSON(src []byte) error
}

//go:generate go run github.com/dmarkham/enumer -type ExcomType -trimprefix EXCOM_
const (
	// bitmasks
	EXCOM_TYPE       ExcomType = 0b1011111100000000
	EXCOM_SUBTYPE    ExcomType = 0b0000000011111111
	EXCOM_TRANSITIVE ExcomType = 0b0100000000000000

	// types
	EXCOM_AS2 ExcomType = 0x0000
	EXCOM_IP4 ExcomType = 0x0100
	EXCOM_AS4 ExcomType = 0x0200

	// subtypes
	EXCOM_TARGET ExcomType = 0x0002
	EXCOM_ORIGIN ExcomType = 0x0003

	// target
	EXCOM_AS2_TARGET ExcomType = EXCOM_AS2 | EXCOM_TARGET
	EXCOM_AS4_TARGET ExcomType = EXCOM_AS4 | EXCOM_TARGET
	EXCOM_IP4_TARGET ExcomType = EXCOM_IP4 | EXCOM_TARGET

	// origin
	EXCOM_AS2_ORIGIN ExcomType = EXCOM_AS2 | EXCOM_ORIGIN
	EXCOM_AS4_ORIGIN ExcomType = EXCOM_AS4 | EXCOM_ORIGIN
	EXCOM_IP4_ORIGIN ExcomType = EXCOM_IP4 | EXCOM_ORIGIN

	// flowspec
	EXCOM_FLOW_RATE_BYTES   ExcomType = 0x8006
	EXCOM_FLOW_RATE_PACKETS ExcomType = 0x800c
	EXCOM_FLOW_ACTION       ExcomType = 0x8007
	EXCOM_FLOW_REDIRECT_AS2 ExcomType = 0x8008
	EXCOM_FLOW_REDIRECT_IP4 ExcomType = 0x8108
	EXCOM_FLOW_REDIRECT_AS4 ExcomType = 0x8208
	EXCOM_FLOW_REDIRECT_NH  ExcomType = 0x0800 // draft-simpson-idr-flowspec-redirect-02.txt
	EXCOM_FLOW_DSCP         ExcomType = 0x8009
)

// ExcomNewFunc returns a new ExcomValue for given type
type ExcomNewFunc func(ExcomType) ExcomValue

// ExcomNew maps extended community types to their new func
var ExcomNew = map[ExcomType]ExcomNewFunc{
	// flowspec
	EXCOM_FLOW_RATE_BYTES:   NewExcomFlowRate,
	EXCOM_FLOW_RATE_PACKETS: NewExcomFlowRate,
	EXCOM_FLOW_ACTION:       NewExcomFlowAction,
	EXCOM_FLOW_REDIRECT_AS2: NewExcomASN,
	EXCOM_FLOW_REDIRECT_IP4: NewExcomAddr,
	EXCOM_FLOW_REDIRECT_AS4: NewExcomASN,
	EXCOM_FLOW_REDIRECT_NH:  NewExcomFlowRedirectNH,
	EXCOM_FLOW_DSCP:         NewExcomFlowDSCP,

	// generic type NewExcomrs
	EXCOM_AS2: NewExcomASN,
	EXCOM_AS4: NewExcomASN,
	EXCOM_IP4: NewExcomAddr,
}

// Value returns et with the transitive bit set to 0 (meaning transitive across ASes)
func (et ExcomType) Value() ExcomType {
	return et & (^EXCOM_TRANSITIVE)
}

// IsTransitive returns true iff et is transitive across ASes
func (et ExcomType) IsTransitive() bool {
	return et&EXCOM_TRANSITIVE == 0
}

// Type returns et with the transitive bit and subtype set to 0
func (et ExcomType) Type() ExcomType {
	return et & EXCOM_TYPE
}

// Subtype returns et with the type set to 0
func (et ExcomType) Subtype() ExcomType {
	return et & EXCOM_SUBTYPE
}

func (et ExcomType) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	if name, ok := ExcomTypeName[et.Value()]; ok {
		dst = append(dst, name...)
	} else {
		dst = append(dst, `0x`...)
		dst = strconv.AppendUint(dst, uint64(et), 16)
	}
	return append(dst, '"')
}

func (et *ExcomType) FromJSON(src []byte) error {
	ss := bs(unq(src))
	if v, ok := ExcomTypeValue[ss]; ok {
		*et = v
	} else {
		v, err := strconv.ParseUint(ss, 0, 16)
		if err != nil {
			return err
		}
		*et = ExcomType(v)
	}
	return nil
}

func NewAttrExtCom(at AttrType) Attr {
	return &AttrExtCom{AttrType: at}
}

func (a *AttrExtCom) Unmarshal(buf []byte, caps Caps) error {
	for len(buf) > 0 {
		if len(buf) < 8 {
			return ErrLength
		}

		// read
		u64 := msb.Uint64(buf)
		et := ExcomType(u64 >> 48)     // take the top 2 bytes
		u64 = u64 & 0x0000ffffffffffff // leave the bottom 6 bytes
		buf = buf[8:]                  // next ext com.

		// interpret and store
		var val ExcomValue
		if newfunc, ok := ExcomNew[et.Value()]; ok {
			val = newfunc(et.Value())
		} else if cb, ok := ExcomNew[et.Type()]; ok {
			val = cb(et.Type())
		} else {
			val = NewExcomRaw(et)
		}
		err := val.Unmarshal(u64)
		if err != nil {
			return err
		}

		a.Add(et, val)
	}

	return nil
}

func (a *AttrExtCom) Marshal(dst []byte, caps Caps) []byte {
	tl := 8 * len(a.Type)
	dst = a.AttrType.MarshalLen(dst, tl)
	for i := range a.Type {
		et, val := a.Type[i], a.Value[i]
		if val == nil {
			continue
		}

		u64 := val.Marshal(caps)
		u64 &= 0x0000ffffffffffff // zero the top 2 bytes
		u64 |= uint64(et) << 48   // set the top 2 bytes to typ
		dst = msb.AppendUint64(dst, u64)
	}
	return dst
}

func (a *AttrExtCom) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	first := true
	for i := range a.Type {
		et, val := a.Type[i], a.Value[i]
		if val == nil {
			continue
		} else if !first {
			dst = append(dst, ',')
		} else {
			first = false
		}

		dst = append(dst, `{"type":`...)
		dst = et.ToJSON(dst)

		dst = append(dst, `,"value":`...)
		dst = val.ToJSON(dst)

		if !et.IsTransitive() {
			dst = append(dst, `,"nontransitive":true`...)
		}

		dst = append(dst, '}')
	}
	return append(dst, ']')
}

func (a *AttrExtCom) FromJSON(src []byte) (reterr error) {
	defer func() {
		if r := recover(); r != nil {
			reterr = fmt.Errorf("%w: %v", ErrValue, r)
		}
	}()

	jsp.ArrayEach(src, func(value []byte, dataType jsp.ValueType, _ int, _ error) {
		if dataType != jsp.Object {
			panic("not an object")
		}

		// get community type
		var et ExcomType
		v, _, _, err := jsp.Get(value, "type")
		if err != nil {
			panic("could not get type")
		} else if et.FromJSON(v) != nil {
			panic("could not parse type")
		}

		// transitive? (best-effort)
		nont, _ := jsp.GetBoolean(value, "nontransitive")
		if !nont {
			et |= EXCOM_TRANSITIVE
		}

		// get community value
		v, _, _, err = jsp.Get(value, "value")
		if err != nil {
			panic("could not get value")
		}

		// parse the value
		var val ExcomValue
		if newfunc, ok := ExcomNew[et.Value()]; ok {
			val = newfunc(et.Value())
		} else if newfunc, ok := ExcomNew[et.Type()]; ok {
			val = newfunc(et.Type())
		} else {
			val = NewExcomRaw(et)
		}
		if err := val.FromJSON(v); err != nil {
			panic(err.Error())
		}

		// store
		a.Type = append(a.Type, et)
		a.Value = append(a.Value, val)
	})
	return
}

// Add appends extended community type et with value val
func (a *AttrExtCom) Add(et ExcomType, val ExcomValue) {
	a.Type = append(a.Type, et)
	a.Value = append(a.Value, val)
}

// Drop drops extended community type et
func (a *AttrExtCom) Drop(et ExcomType) {
	for i, et2 := range a.Type {
		if et2 == et {
			a.Value[i] = nil
		}
	}
}

// Find returns index of community type et, or -1
func (a *AttrExtCom) Find(et ExcomType) int {
	for i, et2 := range a.Type {
		if et2 == et && a.Value[i] != nil {
			return i
		}
	}
	return -1
}

// The basic (raw) Extended Community value
type ExcomRaw struct {
	uint64
}

func NewExcomRaw(et ExcomType) ExcomValue {
	return &ExcomRaw{}
}

func (e *ExcomRaw) Unmarshal(src uint64) error {
	e.uint64 = src
	return nil
}

func (e *ExcomRaw) Marshal(caps Caps) uint64 {
	return uint64(e.uint64 & 0x0000ffffffffffff)
}

func (e *ExcomRaw) ToJSON(dst []byte) []byte {
	dst = append(dst, `"0x`...)
	dst = strconv.AppendUint(dst, uint64(e.uint64&0x0000ffffffffffff), 16)
	return append(dst, '"')
}

func (e *ExcomRaw) FromJSON(src []byte) error {
	v, err := strconv.ParseUint(bs(unq(src)), 0, 48)
	if err == nil {
		e.uint64 = v
	}
	return err
}

// 2- or 4-byte ASN-specific value
type ExcomASN struct {
	et    ExcomType
	ASN   uint32
	Value uint32
}

func NewExcomASN(et ExcomType) ExcomValue {
	return &ExcomASN{et: et}
}

func (e *ExcomASN) Unmarshal(raw uint64) error {
	if e.et.Type()&EXCOM_AS4 != 0 {
		e.ASN = uint32(raw >> 16)
		e.Value = uint32(raw & 0xffff)
	} else {
		e.ASN = uint32(raw >> 32)
		e.Value = uint32(raw)
	}
	return nil
}

func (e *ExcomASN) Marshal(caps Caps) uint64 {
	var raw uint64
	if e.et.Type()&EXCOM_AS4 != 0 {
		raw |= uint64(e.ASN) << 16
		raw |= uint64(e.Value & 0xffff)
	} else {
		raw |= uint64(e.ASN) << 32
		raw |= uint64(e.Value)
	}
	return raw
}

func (e *ExcomASN) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = strconv.AppendUint(dst, uint64(e.ASN), 10)
	dst = append(dst, ':')
	dst = strconv.AppendUint(dst, uint64(e.Value), 10)
	dst = append(dst, '"')
	return dst
}

func (e *ExcomASN) FromJSON(src []byte) error {
	d := bytes.Split(unq(src), []byte(":"))
	if len(d) != 2 {
		return ErrValue
	}

	v, err := strconv.ParseUint(bs(d[0]), 10, 32)
	if err != nil {
		return err
	}
	e.ASN = uint32(v)

	v, err = strconv.ParseUint(bs(d[1]), 10, 32)
	if err != nil {
		return err
	}
	e.Value = uint32(v)

	return nil
}

type ExcomAddr struct {
	Addr  netip.Addr
	Value uint16
}

func NewExcomAddr(et ExcomType) ExcomValue {
	return &ExcomAddr{}
}

func (e *ExcomAddr) Unmarshal(raw uint64) error {
	e.Addr = netip.AddrFrom4([4]byte{
		byte(raw >> 40), byte(raw >> 32),
		byte(raw >> 24), byte(raw >> 16)})
	e.Value = uint16(raw)
	return nil
}

func (e *ExcomAddr) Marshal(caps Caps) uint64 {
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

func (e *ExcomAddr) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = e.Addr.AppendTo(dst)
	dst = append(dst, ':')
	dst = strconv.AppendUint(dst, uint64(e.Value), 10)
	dst = append(dst, '"')
	return dst
}

func (e *ExcomAddr) FromJSON(src []byte) error {
	d := bytes.Split(unq(src), []byte(":"))
	if len(d) != 2 {
		return ErrValue
	}

	a, err := netip.ParseAddr(bs(d[0]))
	if err != nil {
		return err
	}
	e.Addr = a

	v, err := strconv.ParseUint(bs(d[1]), 10, 16)
	if err != nil {
		return err
	}
	e.Value = uint16(v)

	return nil
}

// -------------------

type ExcomFlowRate struct {
	Id   uint16
	Rate float32
}

func NewExcomFlowRate(et ExcomType) ExcomValue {
	return &ExcomFlowRate{}
}

func (e *ExcomFlowRate) Unmarshal(raw uint64) error {
	e.Id = uint16(raw >> 32)
	e.Rate = math.Float32frombits(uint32(raw))
	return nil
}

func (e *ExcomFlowRate) Marshal(caps Caps) uint64 {
	var raw uint64
	raw |= uint64(e.Id) << 32
	raw |= uint64(math.Float32bits(e.Rate))
	return raw
}

func (e *ExcomFlowRate) ToJSON(dst []byte) []byte {
	if e.Id != 0 {
		dst = append(dst, '"')
		dst = strconv.AppendUint(dst, uint64(e.Id), 10)
		dst = append(dst, ':')
	}
	dst = strconv.AppendFloat(dst, float64(e.Rate), 'f', -1, 32)
	if e.Id != 0 {
		dst = append(dst, '"')
	}
	return dst
}

func (e *ExcomFlowRate) FromJSON(src []byte) error {
	d := bytes.Split(unq(src), []byte(":"))
	if len(d) == 2 {
		v, err := strconv.ParseUint(bs(d[0]), 10, 16)
		if err != nil {
			return err
		}
		e.Id = uint16(v)
		d = d[1:]
	} else if len(d) != 1 {
		return ErrValue
	}

	v, err := strconv.ParseFloat(bs(d[0]), 32)
	if err != nil {
		return err
	}
	e.Rate = float32(v)

	return nil
}

// SetFlowRateBytes overwrites EXCOM_FLOW_RATE_BYTES value
func (a *AttrExtCom) SetFlowRateBytes(rate float32) {
	a.Drop(EXCOM_FLOW_RATE_BYTES)
	a.Add(EXCOM_FLOW_RATE_BYTES, &ExcomFlowRate{Rate: rate})
}

// SetFlowRateBytes overwrites EXCOM_FLOW_RATE_PACKETS value
func (a *AttrExtCom) SetFlowRatePackets(rate float32) {
	a.Drop(EXCOM_FLOW_RATE_PACKETS)
	a.Add(EXCOM_FLOW_RATE_PACKETS, &ExcomFlowRate{Rate: rate})
}

type ExcomFlowAction struct {
	Terminal bool // if set, keep collecting rules and apply all that match
	Sample   bool // if set, enable sampling and logging
}

const (
	EXCOM_FLOW_ACTION_TERMINAL = 0b00000001
	EXCOM_FLOW_ACTION_SAMPLE   = 0b00000010
)

func NewExcomFlowAction(et ExcomType) ExcomValue {
	return &ExcomFlowAction{}
}

func (e *ExcomFlowAction) Unmarshal(raw uint64) error {
	e.Terminal = raw&EXCOM_FLOW_ACTION_TERMINAL != 0
	e.Sample = raw&EXCOM_FLOW_ACTION_SAMPLE != 0
	return nil
}

func (e *ExcomFlowAction) Marshal(caps Caps) uint64 {
	var raw uint64
	if e.Terminal {
		raw |= EXCOM_FLOW_ACTION_TERMINAL
	}
	if e.Sample {
		raw |= EXCOM_FLOW_ACTION_SAMPLE
	}
	return raw
}

func (e *ExcomFlowAction) ToJSON(dst []byte) []byte {
	dst = append(dst, `{"terminal":`...)
	dst = jsonBool(dst, e.Terminal)
	dst = append(dst, `,"sample":`...)
	dst = jsonBool(dst, e.Sample)
	dst = append(dst, '}')
	return dst
}

func (e *ExcomFlowAction) FromJSON(src []byte) error {
	if v, _ := jsp.GetBoolean(src, "terminal"); v {
		e.Terminal = true
	}
	if v, _ := jsp.GetBoolean(src, "sample"); v {
		e.Sample = true
	}
	return nil
}

type ExcomFlowRedirectNH struct {
	Copy bool
}

func NewExcomFlowRedirectNH(et ExcomType) ExcomValue {
	return &ExcomFlowRedirectNH{}
}

func (e *ExcomFlowRedirectNH) Unmarshal(raw uint64) error {
	e.Copy = raw&0x01 != 0
	return nil
}

func (e *ExcomFlowRedirectNH) Marshal(caps Caps) uint64 {
	var raw uint64
	if e.Copy {
		raw |= 0x01
	}
	return raw
}

func (e *ExcomFlowRedirectNH) ToJSON(dst []byte) []byte {
	dst = append(dst, `{"copy":`...)
	dst = jsonBool(dst, e.Copy)
	dst = append(dst, '}')
	return dst
}

func (e *ExcomFlowRedirectNH) FromJSON(src []byte) error {
	if v, _ := jsp.GetBoolean(src, "copy"); v {
		e.Copy = true
	}
	return nil
}

type ExcomFlowDSCP struct {
	DSCP uint8
}

func NewExcomFlowDSCP(et ExcomType) ExcomValue {
	return &ExcomFlowDSCP{}
}

func (e *ExcomFlowDSCP) Unmarshal(raw uint64) error {
	e.DSCP = uint8(raw & 0b00111111)
	return nil
}

func (e *ExcomFlowDSCP) Marshal(caps Caps) uint64 {
	var raw uint64
	raw |= uint64(e.DSCP & 0b00111111)
	return raw
}

func (e *ExcomFlowDSCP) ToJSON(dst []byte) []byte {
	dst = strconv.AppendUint(dst, uint64(e.DSCP), 10)
	return dst
}

func (e *ExcomFlowDSCP) FromJSON(src []byte) error {
	v, err := strconv.ParseUint(bs(unq(src)), 0, 6)
	if err == nil {
		e.DSCP = uint8(v)
	}
	return err
}
