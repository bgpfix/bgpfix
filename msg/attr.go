package msg

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	jsp "github.com/buger/jsonparser"
)

// Attr describes a BGP path attribute
type Attr interface {
	// Code returns attribute code
	Code() AttrCode

	// Flags returns attribute flags
	Flags() AttrFlags

	// SetFlags sets attribute flags
	SetFlags(AttrFlags)

	// Unmarshal parses wire representation from src
	Unmarshal(src []byte, caps Caps) error

	// Marshal appends wire representation to dst: type(16), length(8/16), and value
	Marshal(dst []byte, caps Caps) []byte

	// ToJSON appends JSON representation of the value to dst
	ToJSON(dst []byte) []byte

	// FromJSON reads from JSON represetnation in src
	FromJSON(src []byte) error
}

type (
	// AttrFlags holds attribute flags
	AttrFlags byte

	// AttrCode holds attribute type code
	AttrCode byte

	// AttrType holds attribute flags (MSB) and type code (LSB)
	AttrType uint16
)

//go:generate go run github.com/dmarkham/enumer -type=AttrCode -trimprefix ATTR_
const (
	// attribute flags
	ATTR_OPTIONAL   AttrFlags = 0b10000000
	ATTR_TRANSITIVE AttrFlags = 0b01000000
	ATTR_PARTIAL    AttrFlags = 0b00100000
	ATTR_EXTENDED   AttrFlags = 0b00010000
	ATTR_UNUSED     AttrFlags = 0b00001111

	// attribute codes
	ATTR_UNSPECIFIED        AttrCode = 0
	ATTR_ORIGIN             AttrCode = 1
	ATTR_ASPATH             AttrCode = 2
	ATTR_NEXTHOP            AttrCode = 3
	ATTR_MED                AttrCode = 4
	ATTR_LOCALPREF          AttrCode = 5
	ATTR_AGGREGATE          AttrCode = 6
	ATTR_AGGREGATOR         AttrCode = 7
	ATTR_COMMUNITY          AttrCode = 8
	ATTR_ORIGINATOR         AttrCode = 9
	ATTR_CLUSTER_LIST       AttrCode = 10
	ATTR_MP_REACH           AttrCode = 14
	ATTR_MP_UNREACH         AttrCode = 15
	ATTR_EXT_COMMUNITY      AttrCode = 16
	ATTR_AS4PATH            AttrCode = 17
	ATTR_AS4AGGREGATOR      AttrCode = 18
	ATTR_PMSI_TUNNEL        AttrCode = 22
	ATTR_TUNNEL             AttrCode = 23
	ATTR_TRAFFIC_ENG        AttrCode = 24
	ATTR_IPV6_EXT_COMMUNITY AttrCode = 25
	ATTR_AIGP               AttrCode = 26
	ATTR_PE_DISTING         AttrCode = 27
	ATTR_BGP_LS             AttrCode = 29
	ATTR_LARGE_COMMUNITY    AttrCode = 32
	ATTR_BGPSEC_PATH        AttrCode = 33
	ATTR_OTC                AttrCode = 35
	ATTR_DPATH              AttrCode = 36
	ATTR_SFP_ATTR           AttrCode = 37
	ATTR_BFD_DISCRIMINATOR  AttrCode = 38
	ATTR_RCA                AttrCode = 39
	ATTR_PREFIX_SID         AttrCode = 40
	ATTR_SET                AttrCode = 128
)

// AttrNewFunc returns new Attr for given type at.
type AttrNewFunc func(at AttrType) Attr

// AttrNew maps attribute codes to their NewFunc
var AttrNew = map[AttrCode]AttrNewFunc{
	ATTR_ORIGIN:          NewAttrOrigin,
	ATTR_ASPATH:          NewAttrAspath,
	ATTR_AS4PATH:         NewAttrAspath,
	ATTR_NEXTHOP:         NewAttrIP4,
	ATTR_MED:             NewAttrU32,
	ATTR_LOCALPREF:       NewAttrU32,
	ATTR_MP_REACH:        NewAttrMP,
	ATTR_MP_UNREACH:      NewAttrMP,
	ATTR_COMMUNITY:       NewAttrCommunity,
	ATTR_EXT_COMMUNITY:   NewAttrExtCom,
	ATTR_LARGE_COMMUNITY: NewAttrLargeCom,
	ATTR_AGGREGATOR:      NewAttrAggregator,
	ATTR_AS4AGGREGATOR:   NewAttrAggregator,
	ATTR_ORIGINATOR:      NewAttrIP4,
	ATTR_CLUSTER_LIST:    NewAttrIPList4,
}

// AttrDefaultFlags gives the default flags for attribute codes, in addition to ATTR_OPTIONAL
var AttrDefaultFlags = map[AttrCode]AttrFlags{
	ATTR_COMMUNITY:       ATTR_TRANSITIVE,
	ATTR_EXT_COMMUNITY:   ATTR_TRANSITIVE,
	ATTR_LARGE_COMMUNITY: ATTR_TRANSITIVE,
	ATTR_AGGREGATOR:      ATTR_TRANSITIVE,
}

// NewAttrType returns attribute type for given code and flags.
// If flags is 0, we try to come up with a default value for them.
func NewAttrType(code AttrCode, flags AttrFlags) AttrType {
	if flags == 0 {
		switch code {
		case ATTR_ORIGIN, ATTR_ASPATH, ATTR_NEXTHOP, ATTR_LOCALPREF, ATTR_AGGREGATE:
			flags = ATTR_TRANSITIVE
		default:
			flags = ATTR_OPTIONAL | AttrDefaultFlags[code]
		}
	}
	return AttrType(flags)<<8 | AttrType(code)
}

// Code returns at code (eg. ATTR_NEXTHOP)
func (at AttrType) Code() AttrCode {
	return AttrCode(at)
}

// Flags returns at flags (eg. ATTR_TRANSITIVE)
func (at AttrType) Flags() AttrFlags {
	return AttrFlags(at >> 8)
}

// SetFlags overwrites flags
func (at *AttrType) SetFlags(flags AttrFlags) {
	*at = AttrType(flags)<<8 | AttrType(at.Code())
}

// HasFlags returns true iff af has (at least one of) flags set
func (at AttrType) HasFlags(flags AttrFlags) bool {
	return AttrFlags(at>>8)&flags != 0
}

// MarshalLen appends to dst attribute flags, code, and length
// FIXME: switch to always extended and write real length after (defer retfunc?)
func (at AttrType) MarshalLen(dst []byte, length int) []byte {
	flags := at.Flags()
	if length > 0xff {
		flags |= ATTR_EXTENDED
	} else {
		flags &= ^ATTR_EXTENDED
	}
	dst = append(dst, byte(flags), byte(at.Code()))
	if length > 0xff {
		dst = msb.AppendUint16(dst, uint16(length))
	} else {
		dst = append(dst, byte(length))
	}
	return dst
}

// ToJSON() appends ac name as a JSON string to dst
func (ac AttrCode) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	if name, ok := AttrCodeName[ac]; ok {
		dst = append(dst, name...)
	} else {
		dst = append(dst, `ATTR_`...)
		dst = jsonByte(dst, byte(ac))
	}
	return append(dst, '"')
}

// FromJSON() sets ac from JSON in src
func (ac *AttrCode) FromJSON(src []byte) error {
	name := bsu(src)
	if val, ok := AttrCodeValue[name]; ok {
		*ac = val
	} else if aft, ok := strings.CutPrefix(name, `ATTR_`); ok {
		val, err := strconv.ParseUint(aft, 0, 8)
		if err != nil {
			return err
		}
		*ac = AttrCode(val)
	} else {
		return ErrValue
	}
	return nil
}

func (af AttrFlags) ToJSON(dst []byte) []byte {
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

func (af *AttrFlags) FromJSON(src []byte) error {
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
			*af |= AttrFlags(fv)
			return err
		}
	}
	return nil
}

// Attrs represents BGP path attributes
type Attrs struct {
	db map[AttrCode]Attr
}

// Init initializes Attrs. Can be called multiple times for lazy init.
func (attrs *Attrs) Init() {
	if attrs.db == nil {
		attrs.db = map[AttrCode]Attr{}
	}
}

// Valid returns true iff Attrs has already been initialized
func (attrs *Attrs) Valid() bool {
	return attrs.db != nil
}

// Reset resets Attrs back to initial state.
func (attrs *Attrs) Reset() {
	attrs.db = nil
}

// Clear drops all attributes.
func (attrs *Attrs) Clear() {
	if attrs.Valid() {
		clear(attrs.db)
	}
}

// Len returns the number of attributes
func (attrs *Attrs) Len() int {
	if attrs.Valid() {
		return len(attrs.db)
	} else {
		return 0
	}
}

// SetFrom sets all attributes from src, overwriting attrs[ac] for existing attribute codes
func (attrs *Attrs) SetFrom(src Attrs) {
	if !src.Valid() {
		return
	}

	attrs.Init()
	for ac, att := range attrs.db {
		attrs.db[ac] = att
	}
}

// Get returns attrs[ac] or nil if not possible.
func (attrs *Attrs) Get(ac AttrCode) Attr {
	if attrs.Valid() {
		return attrs.db[ac]
	} else {
		return nil
	}
}

// Has returns true iff attrs[ac] is set and non-nil
func (attrs *Attrs) Has(ac AttrCode) bool {
	return attrs.Get(ac) != nil
}

// Drop drops attrs[ac].
func (attrs *Attrs) Drop(ac AttrCode) {
	if attrs.Valid() {
		delete(attrs.db, ac)
	}
}

// Set overwrites attrs[ac] with value.
func (attrs *Attrs) Set(ac AttrCode, value Attr) {
	attrs.Init()
	attrs.db[ac] = value
}

// Use returns attrs[ac] if its already set and non-nil.
// Otherwise, it adds a new instance for ac with default flags.
func (attrs *Attrs) Use(ac AttrCode) Attr {
	// already there?
	if attrs.Valid() {
		if att, ok := attrs.db[ac]; ok && att != nil {
			return att
		}
	} else {
		attrs.Init()
	}

	// select the new func, default to raw
	newfunc, ok := AttrNew[ac]
	if !ok {
		newfunc = NewAttrRaw
	}

	// create, store, and return
	att := newfunc(NewAttrType(ac, 0))
	attrs.db[ac] = att
	return att
}

// Each executes cb for each attribute in attrs,
// in an ascending order of attribute codes.
func (attrs *Attrs) Each(cb func(i int, ac AttrCode, att Attr)) {
	if !attrs.Valid() {
		return
	}

	// dump attrs into todo
	type attcode struct {
		ac  AttrCode
		att Attr
	}
	var todo []attcode
	for ac, att := range attrs.db {
		if att != nil {
			todo = append(todo, attcode{ac, att})
		}
	}

	// sort todo
	sort.Slice(todo, func(i, j int) bool {
		return todo[i].ac < todo[j].ac
	})

	// run
	for i, c := range todo {
		cb(i, c.ac, c.att)
	}
}

func (attrs *Attrs) MarshalJSON() ([]byte, error) {
	return attrs.ToJSON(nil), nil
}

func (attrs *Attrs) ToJSON(dst []byte) []byte {
	if !attrs.Valid() {
		return append(dst, "null"...)
	}

	dst = append(dst, '{')
	attrs.Each(func(i int, ac AttrCode, att Attr) {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = ac.ToJSON(dst)

		dst = append(dst, `:{"flags":`...)
		dst = att.Flags().ToJSON(dst)

		dst = append(dst, `,"value":`...)
		dst = att.ToJSON(dst)
		dst = append(dst, '}')
	})
	return append(dst, '}')
}

func (attrs *Attrs) FromJSON(src []byte) error {
	mkerr := func(key []byte, err error) error {
		return fmt.Errorf("attrs[%s]: %w", key, err)
	}

	return jsp.ObjectEach(src, func(key, val []byte, _ jsp.ValueType, _ int) error {
		// is key a valid attribute code?
		var acode AttrCode
		if acode.FromJSON(key) != nil {
			return mkerr(key, ErrAttrCode)
		}
		attr := attrs.Use(acode)

		// fetch the value and flags
		fval, _, _, ferr := jsp.Get(val, "flags")
		vval, _, _, verr := jsp.Get(val, "value")

		// has flags?
		if ferr == nil {
			var af AttrFlags
			if af.FromJSON(fval) != nil {
				return mkerr(key, ErrAttrFlags)
			}
			attr.SetFlags(af)
		} else { // use default flags, try to use whole buf as vval
			vval = val
			verr = nil
		}

		// has the value?
		if verr != nil || len(vval) == 0 {
			return mkerr(key, ErrValue)
		}

		// parse
		if err := attr.FromJSON(vval); err != nil {
			return mkerr(key, err)
		}
		return nil
	})
}
