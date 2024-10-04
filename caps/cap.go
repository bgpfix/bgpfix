package caps

import (
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/json"
)

// Code represents BGP capability code
type Code byte

// capability codes
const (
	CAP_UNSPECIFIED            Code = 0
	CAP_MP                     Code = 1
	CAP_ROUTE_REFRESH          Code = 2
	CAP_OUTBOUND_FILTERING     Code = 3
	CAP_EXTENDED_NEXTHOP       Code = 5
	CAP_EXTENDED_MESSAGE       Code = 6
	CAP_BGPSEC                 Code = 7
	CAP_MULTIPLE_LABELS        Code = 8
	CAP_ROLE                   Code = 9
	CAP_GRACEFUL_RESTART       Code = 64
	CAP_AS4                    Code = 65
	CAP_DYNAMIC                Code = 67
	CAP_MULTISESSION           Code = 68
	CAP_ADDPATH                Code = 69
	CAP_ENHANCED_ROUTE_REFRESH Code = 70
	CAP_LLGR                   Code = 71
	CAP_ROUTING_POLICY         Code = 72
	CAP_FQDN                   Code = 73
	CAP_BFD                    Code = 74
	CAP_VERSION                Code = 75
	CAP_PRE_ROUTE_REFRESH      Code = 128
)

//go:generate go run github.com/dmarkham/enumer -type=Code -trimprefix CAP_

// Cap represents a particular BGP capability
type Cap interface {
	// Unmarshal parses wire representation from src.
	// It must support multiple calls for the same message.
	Unmarshal(src []byte, caps Caps) error

	// Marshal appends wire representation to dst, including code and length.
	// Return nil to skip this capability.
	Marshal(dst []byte) []byte

	// ToJSON appends JSON representation of the value to dst
	ToJSON(dst []byte) []byte

	// FromJSON reads from JSON representation in src
	FromJSON(src []byte) error

	// Intersect returns a new instance that represents its intersection with cap2.
	// This is used during capability negotiation. Return nil if equal or N/A.
	// When needed, assume cap2 is what was sent in the L direction.
	Intersect(cap2 Cap) Cap
}

// NewFunc returns a new instance of capability cc.
type NewFunc func(cc Code) Cap

// NewFuncs maps capability codes to their new func
var NewFuncs = map[Code]NewFunc{
	CAP_MP:               NewMP,
	CAP_AS4:              NewAS4,
	CAP_EXTENDED_NEXTHOP: NewExtNH,
	CAP_FQDN:             NewFqdn,
	CAP_ADDPATH:          NewAddPath,
}

// NewCap returns a new Cap instance for given code cc
func NewCap(cc Code) Cap {
	// select the new func, default to raw
	newfunc, ok := NewFuncs[cc]
	if !ok {
		newfunc = NewRaw
	}

	// call the newfunc with proper attr type value
	return newfunc(cc)
}

// ToJSON() appends cc name as a JSON string to dst
func (cc Code) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	if name, ok := CodeName[cc]; ok {
		dst = append(dst, name...)
	} else {
		dst = append(dst, `CAP_`...)
		dst = json.Byte(dst, byte(cc))
	}
	return append(dst, '"')
}

// FromJSON() sets ac from JSON in src
func (cc *Code) FromJSON(src string) error {
	if val, ok := CodeValue[src]; ok {
		*cc = val
	} else if aft, ok := strings.CutPrefix(src, `CAP_`); ok {
		val, err := strconv.ParseUint(aft, 0, 8)
		if err != nil {
			return err
		}
		*cc = Code(val)
	} else {
		return ErrValue
	}
	return nil
}
