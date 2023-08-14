package caps

// Cap represents a particular BGP capability
type Cap interface {
	// Common returns a new instance of the same capability that
	// represents its intersection with cap2.
	//
	// May return nil, eg. if cap and cap2 are equal.
	Common(cap2 Cap) Cap

	// Unmarshal parses wire representation from src.
	// It must support multiple calls for the same message.
	Unmarshal(src []byte, caps Caps) error

	// Marshal appends wire representation to dst, including code and length
	Marshal(dst []byte) []byte

	// ToJSON appends JSON representation of the value to dst
	ToJSON(dst []byte) []byte
}

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

// NewFunc returns a new instance of capability cc.
type NewFunc func(cc Code) Cap

// NewFuncs maps capability codes to their new func
var NewFuncs = map[Code]NewFunc{
	CAP_MP:               NewMP,
	CAP_AS4:              NewAS4,
	CAP_EXTENDED_NEXTHOP: NewExtNH,
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
