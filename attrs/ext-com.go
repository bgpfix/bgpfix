package attrs

import (
	"fmt"
	"strconv"

	"github.com/bgpfix/bgpfix/caps"
	jsp "github.com/buger/jsonparser"
)

// ExtCom represents ATTR_EXT_COMMUNITY
type ExtCom struct {
	CodeFlags

	Type  []ExtcomType  // top 2 bytes (always the "Extended" type)
	Value []ExtcomValue // bottom 6 bytes
}

// Extended Community Type
type ExtcomType uint16

// Extended Community Value
type ExtcomValue interface {
	// Unmarshal NewExtcoms wire representation from src
	Unmarshal(src uint64) error

	// Marshal returns wire representation of the value
	Marshal(cps caps.Caps) uint64

	// ToJSON appends JSON representation of the value to dst
	ToJSON(dst []byte) []byte

	// FromJSON reads value from JSON representation in src
	FromJSON(src []byte) error
}

const (
	// bitmasks
	EXTCOM_TYPE       ExtcomType = 0b1011111100000000
	EXTCOM_SUBTYPE    ExtcomType = 0b0000000011111111
	EXTCOM_TRANSITIVE ExtcomType = 0b0100000000000000

	// types
	EXTCOM_AS2 ExtcomType = 0x0000
	EXTCOM_IP4 ExtcomType = 0x0100
	EXTCOM_AS4 ExtcomType = 0x0200

	// subtypes
	EXTCOM_TARGET ExtcomType = 0x0002
	EXTCOM_ORIGIN ExtcomType = 0x0003

	// target
	EXTCOM_AS2_TARGET ExtcomType = EXTCOM_AS2 | EXTCOM_TARGET
	EXTCOM_AS4_TARGET ExtcomType = EXTCOM_AS4 | EXTCOM_TARGET
	EXTCOM_IP4_TARGET ExtcomType = EXTCOM_IP4 | EXTCOM_TARGET

	// origin
	EXTCOM_AS2_ORIGIN ExtcomType = EXTCOM_AS2 | EXTCOM_ORIGIN
	EXTCOM_AS4_ORIGIN ExtcomType = EXTCOM_AS4 | EXTCOM_ORIGIN
	EXTCOM_IP4_ORIGIN ExtcomType = EXTCOM_IP4 | EXTCOM_ORIGIN

	// flowspec
	EXTCOM_FLOW_RATE_BYTES   ExtcomType = 0x8006
	EXTCOM_FLOW_RATE_PACKETS ExtcomType = 0x800c
	EXTCOM_FLOW_ACTION       ExtcomType = 0x8007
	EXTCOM_FLOW_REDIRECT_AS2 ExtcomType = 0x8008
	EXTCOM_FLOW_REDIRECT_IP4 ExtcomType = 0x8108
	EXTCOM_FLOW_REDIRECT_AS4 ExtcomType = 0x8208
	EXTCOM_FLOW_REDIRECT_NH  ExtcomType = 0x0800 // draft-simpson-idr-flowspec-redirect-02.txt
	EXTCOM_FLOW_DSCP         ExtcomType = 0x8009
)

//go:generate go run github.com/dmarkham/enumer -type ExtcomType -trimprefix EXTCOM_

// ExtcomNewFunc returns a new ExtcomValue for given type
type ExtcomNewFunc func(ExtcomType) ExtcomValue

// ExtcomNewFuncs maps extended community types to their new func
var ExtcomNewFuncs = map[ExtcomType]ExtcomNewFunc{
	// flowspec
	EXTCOM_FLOW_RATE_BYTES:   NewExtcomFlowRate,
	EXTCOM_FLOW_RATE_PACKETS: NewExtcomFlowRate,
	EXTCOM_FLOW_ACTION:       NewExtcomFlowAction,
	EXTCOM_FLOW_REDIRECT_AS2: NewExtcomASN,
	EXTCOM_FLOW_REDIRECT_IP4: NewExtcomAddr,
	EXTCOM_FLOW_REDIRECT_AS4: NewExtcomASN,
	EXTCOM_FLOW_REDIRECT_NH:  NewExtcomFlowRedirectNH,
	EXTCOM_FLOW_DSCP:         NewExtcomFlowDSCP,

	// generic type NewExtcomrs
	EXTCOM_AS2: NewExtcomASN,
	EXTCOM_AS4: NewExtcomASN,
	EXTCOM_IP4: NewExtcomAddr,
}

// Value returns et with the transitive bit set to 0 (meaning transitive across ASes)
func (et ExtcomType) Value() ExtcomType {
	return et & (^EXTCOM_TRANSITIVE)
}

// IsTransitive returns true iff et is transitive across ASes
func (et ExtcomType) IsTransitive() bool {
	return et&EXTCOM_TRANSITIVE == 0
}

// Type returns et with the transitive bit and subtype set to 0
func (et ExtcomType) Type() ExtcomType {
	return et & EXTCOM_TYPE
}

// Subtype returns et with the type set to 0
func (et ExtcomType) Subtype() ExtcomType {
	return et & EXTCOM_SUBTYPE
}

func (et ExtcomType) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	if name, ok := ExtcomTypeName[et.Value()]; ok {
		dst = append(dst, name...)
	} else {
		dst = append(dst, `0x`...)
		dst = strconv.AppendUint(dst, uint64(et), 16)
	}
	return append(dst, '"')
}

func (et *ExtcomType) FromJSON(src []byte) error {
	ss := bs(unq(src))
	if v, ok := ExtcomTypeValue[ss]; ok {
		*et = v
	} else {
		v, err := strconv.ParseUint(ss, 0, 16)
		if err != nil {
			return err
		}
		*et = ExtcomType(v)
	}
	return nil
}

func NewExtCom(at CodeFlags) Attr {
	return &ExtCom{CodeFlags: at}
}

func (a *ExtCom) Unmarshal(buf []byte, cps caps.Caps) error {
	for len(buf) > 0 {
		if len(buf) < 8 {
			return ErrLength
		}

		// read
		u64 := msb.Uint64(buf)
		et := ExtcomType(u64 >> 48)    // take the top 2 bytes
		u64 = u64 & 0x0000ffffffffffff // leave the bottom 6 bytes
		buf = buf[8:]                  // next ext com.

		// interpret and store
		var val ExtcomValue
		if newfunc, ok := ExtcomNewFuncs[et.Value()]; ok {
			val = newfunc(et.Value())
		} else if cb, ok := ExtcomNewFuncs[et.Type()]; ok {
			val = cb(et.Type())
		} else {
			val = NewExtcomRaw(et)
		}
		err := val.Unmarshal(u64)
		if err != nil {
			return err
		}

		a.Add(et, val)
	}

	return nil
}

func (a *ExtCom) Marshal(dst []byte, cps caps.Caps) []byte {
	tl := 8 * len(a.Type)
	dst = a.CodeFlags.MarshalLen(dst, tl)
	for i := range a.Type {
		et, val := a.Type[i], a.Value[i]
		if val == nil {
			continue
		}

		u64 := val.Marshal(cps)
		u64 &= 0x0000ffffffffffff // zero the top 2 bytes
		u64 |= uint64(et) << 48   // set the top 2 bytes to typ
		dst = msb.AppendUint64(dst, u64)
	}
	return dst
}

func (a *ExtCom) ToJSON(dst []byte) []byte {
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

func (a *ExtCom) FromJSON(src []byte) (reterr error) {
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
		var et ExtcomType
		v, _, _, err := jsp.Get(value, "type")
		if err != nil {
			panic("could not get type")
		} else if et.FromJSON(v) != nil {
			panic("could not parse type")
		}

		// transitive? (best-effort)
		nont, _ := jsp.GetBoolean(value, "nontransitive")
		if !nont {
			et |= EXTCOM_TRANSITIVE
		}

		// get community value
		v, _, _, err = jsp.Get(value, "value")
		if err != nil {
			panic("could not get value")
		}

		// parse the value
		var val ExtcomValue
		if newfunc, ok := ExtcomNewFuncs[et.Value()]; ok {
			val = newfunc(et.Value())
		} else if newfunc, ok := ExtcomNewFuncs[et.Type()]; ok {
			val = newfunc(et.Type())
		} else {
			val = NewExtcomRaw(et)
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
func (a *ExtCom) Add(et ExtcomType, val ExtcomValue) {
	a.Type = append(a.Type, et)
	a.Value = append(a.Value, val)
}

// Drop drops extended community type et
func (a *ExtCom) Drop(et ExtcomType) {
	for i, et2 := range a.Type {
		if et2 == et {
			a.Value[i] = nil
		}
	}
}

// Find returns index of community type et, or -1
func (a *ExtCom) Find(et ExtcomType) int {
	for i, et2 := range a.Type {
		if et2 == et && a.Value[i] != nil {
			return i
		}
	}
	return -1
}
