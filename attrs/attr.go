package attrs

import (
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/caps"
)

// Attr represents a particular BGP path attribute
type Attr interface {
	// Code returns attribute code
	Code() Code

	// Flags returns attribute flags
	Flags() Flags

	// SetFlags sets attribute flags
	SetFlags(Flags)

	// Unmarshal parses wire representation from src
	Unmarshal(src []byte, cps caps.Caps) error

	// Marshal appends wire representation to dst: type(16), length(8/16), and value
	Marshal(dst []byte, cps caps.Caps) []byte

	// ToJSON appends JSON representation of the value to dst
	ToJSON(dst []byte) []byte

	// FromJSON reads from JSON represetnation in src
	FromJSON(src []byte) error
}

type (
	// Flags holds attribute flags
	Flags byte

	// Code holds attribute type code
	Code byte

	// CodeFlags holds attribute flags (MSB) and type code (LSB)
	CodeFlags uint16
)

//go:generate go run github.com/dmarkham/enumer -type=Code -trimprefix ATTR_
const (
	// attribute flags
	ATTR_OPTIONAL   Flags = 0b10000000
	ATTR_TRANSITIVE Flags = 0b01000000
	ATTR_PARTIAL    Flags = 0b00100000
	ATTR_EXTENDED   Flags = 0b00010000
	ATTR_UNUSED     Flags = 0b00001111

	// attribute codes
	ATTR_UNSPECIFIED        Code = 0
	ATTR_ORIGIN             Code = 1
	ATTR_ASPATH             Code = 2
	ATTR_NEXTHOP            Code = 3
	ATTR_MED                Code = 4
	ATTR_LOCALPREF          Code = 5
	ATTR_AGGREGATE          Code = 6
	ATTR_AGGREGATOR         Code = 7
	ATTR_COMMUNITY          Code = 8
	ATTR_ORIGINATOR         Code = 9
	ATTR_CLUSTER_LIST       Code = 10
	ATTR_MP_REACH           Code = 14
	ATTR_MP_UNREACH         Code = 15
	ATTR_EXT_COMMUNITY      Code = 16
	ATTR_AS4PATH            Code = 17
	ATTR_AS4AGGREGATOR      Code = 18
	ATTR_PMSI_TUNNEL        Code = 22
	ATTR_TUNNEL             Code = 23
	ATTR_TRAFFIC_ENG        Code = 24
	ATTR_IPV6_EXT_COMMUNITY Code = 25
	ATTR_AIGP               Code = 26
	ATTR_PE_DISTING         Code = 27
	ATTR_BGP_LS             Code = 29
	ATTR_LARGE_COMMUNITY    Code = 32
	ATTR_BGPSEC_PATH        Code = 33
	ATTR_OTC                Code = 35
	ATTR_DPATH              Code = 36
	ATTR_SFP_ATTR           Code = 37
	ATTR_BFD_DISCRIMINATOR  Code = 38
	ATTR_RCA                Code = 39
	ATTR_PREFIX_SID         Code = 40
	ATTR_SET                Code = 128
)

// NewFunc returns new Attr for given type at.
type NewFunc func(cf CodeFlags) Attr

// NewFuncs maps attribute codes to their NewFunc
var NewFuncs = map[Code]NewFunc{
	ATTR_ORIGIN:          NewOrigin,
	ATTR_ASPATH:          NewAspath,
	ATTR_AS4PATH:         NewAspath,
	ATTR_NEXTHOP:         NewIP4,
	ATTR_MED:             NewU32,
	ATTR_LOCALPREF:       NewU32,
	ATTR_MP_REACH:        NewMP,
	ATTR_MP_UNREACH:      NewMP,
	ATTR_COMMUNITY:       NewCommunity,
	ATTR_EXT_COMMUNITY:   NewExtCom,
	ATTR_LARGE_COMMUNITY: NewLargeCom,
	ATTR_AGGREGATOR:      NewAggregator,
	ATTR_AS4AGGREGATOR:   NewAggregator,
	ATTR_ORIGINATOR:      NewIP4,
	ATTR_CLUSTER_LIST:    NewIPList4,
}

// DefaultFlags gives the default flags for attribute codes, in addition to ATTR_OPTIONAL
var DefaultFlags = map[Code]Flags{
	ATTR_COMMUNITY:       ATTR_TRANSITIVE,
	ATTR_EXT_COMMUNITY:   ATTR_TRANSITIVE,
	ATTR_LARGE_COMMUNITY: ATTR_TRANSITIVE,
	ATTR_AGGREGATOR:      ATTR_TRANSITIVE,
}

// NewAttr returns a new Attr instance for given code ac and default flags.
func NewAttr(ac Code) Attr {
	var flags Flags
	switch ac {
	case ATTR_ORIGIN, ATTR_ASPATH, ATTR_NEXTHOP, ATTR_LOCALPREF, ATTR_AGGREGATE:
		flags = ATTR_TRANSITIVE
	default:
		flags = ATTR_OPTIONAL | DefaultFlags[ac]
	}

	// select the new func, default to raw
	newfunc, ok := NewFuncs[ac]
	if !ok {
		newfunc = NewRaw
	}

	// call the newfunc with proper attr type value
	return newfunc(CodeFlags(flags)<<8 | CodeFlags(ac))
}

// Code returns cf code (eg. ATTR_NEXTHOP)
func (cf CodeFlags) Code() Code {
	return Code(cf)
}

// Flags returns cf flags (eg. ATTR_TRANSITIVE)
func (cf CodeFlags) Flags() Flags {
	return Flags(cf >> 8)
}

// SetFlags overwrites flags
func (cf *CodeFlags) SetFlags(af Flags) {
	*cf = CodeFlags(af)<<8 | CodeFlags(cf.Code())
}

// HasFlags returns true iff af has (at least one of) flags set
func (cf CodeFlags) HasFlags(af Flags) bool {
	return Flags(cf>>8)&af != 0
}

// MarshalLen appends to dst attribute flags, code, and length
// FIXME: switch to always extended and write real length after (defer retfunc?)
func (cf CodeFlags) MarshalLen(dst []byte, length int) []byte {
	flags := cf.Flags()
	if length > 0xff {
		flags |= ATTR_EXTENDED
	} else {
		flags &= ^ATTR_EXTENDED
	}
	dst = append(dst, byte(flags), byte(cf.Code()))
	if length > 0xff {
		dst = msb.AppendUint16(dst, uint16(length))
	} else {
		dst = append(dst, byte(length))
	}
	return dst
}

// ToJSON() appends ac name as a JSON string to dst
func (ac Code) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	if name, ok := CodeName[ac]; ok {
		dst = append(dst, name...)
	} else {
		dst = append(dst, `ATTR_`...)
		dst = jsonByte(dst, byte(ac))
	}
	return append(dst, '"')
}

// FromJSON() sets ac from JSON in src
func (ac *Code) FromJSON(src []byte) error {
	name := bsu(src)
	if val, ok := CodeValue[name]; ok {
		*ac = val
	} else if aft, ok := strings.CutPrefix(name, `ATTR_`); ok {
		val, err := strconv.ParseUint(aft, 0, 8)
		if err != nil {
			return err
		}
		*ac = Code(val)
	} else {
		return ErrValue
	}
	return nil
}

func (af Flags) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	if af&ATTR_OPTIONAL != 0 {
		dst = append(dst, 'O')
	}
	if af&ATTR_TRANSITIVE != 0 {
		dst = append(dst, 'T')
	}
	if af&ATTR_PARTIAL != 0 {
		dst = append(dst, 'P')
	}
	if af&ATTR_EXTENDED != 0 {
		dst = append(dst, 'X')
	}
	if v := af & ATTR_UNUSED; v != 0 {
		dst = jsonByte(dst, byte(v))
	}
	return append(dst, '"')
}

func (af *Flags) FromJSON(src []byte) error {
	src = unq(src)
	for i, v := range src {
		switch v {
		case 'O':
			*af |= ATTR_OPTIONAL
		case 'T':
			*af |= ATTR_TRANSITIVE
		case 'P':
			*af |= ATTR_PARTIAL
		case 'X':
			*af |= ATTR_EXTENDED
		default:
			fv, err := unjsonByte(src[i:])
			*af |= Flags(fv)
			return err
		}
	}
	return nil
}
