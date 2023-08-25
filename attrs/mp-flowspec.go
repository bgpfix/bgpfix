package attrs

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/json"
)

// NewMPFlowspec returns, for a parent mp attribute, a new MPValue implementing Flowspec
func NewMPFlowspec(mp *MP) MPValue {
	return &MPFlowspec{MP: mp}
}

// MPFlowspec represents ATTR_MP attributes for RFC8955 and RFC8956 Flowspec
type MPFlowspec struct {
	*MP

	NextHop   netip.Addr // best-effort
	LinkLocal netip.Addr // best-effort
	Rules     []FlowRule // see RFC8955 Fig1
}

// FlowRule represents a Flowspec rule, which is a set of type-value components
type FlowRule map[FlowType]FlowValue

// FlowType represents a Flowspec component type
type FlowType uint8

//go:generate go run github.com/dmarkham/enumer -type FlowType -trimprefix FLOW_
const (
	FLOW_DST       FlowType = 1
	FLOW_SRC       FlowType = 2
	FLOW_PROTO     FlowType = 3
	FLOW_PORT      FlowType = 4
	FLOW_PORT_DST  FlowType = 5
	FLOW_PORT_SRC  FlowType = 6
	FLOW_ICMP_TYPE FlowType = 7
	FLOW_ICMP_CODE FlowType = 8
	FLOW_TCP_FLAGS FlowType = 9
	FLOW_PKTLEN    FlowType = 10
	FLOW_DSCP      FlowType = 11
	FLOW_FRAG      FlowType = 12
	FLOW_LABEL     FlowType = 13
)

// FlowValue represents a Flowspec component value
type FlowValue interface {
	// Unmarshal parses wire representation from src
	Unmarshal(src []byte, cps caps.Caps) (int, error)

	// Marshal appends wire representation to dst, without type
	Marshal(dst []byte, cps caps.Caps) []byte

	// ToJSON appends JSON representation of the component to dst
	ToJSON(dst []byte) []byte

	// FromJSON reads from JSON representation in src
	FromJSON(src []byte) error
}

// FlowNewFunc returns a new FlowValue for given FlowType
type FlowNewFunc func(FlowType) FlowValue

// FlowNewFuncs4 maps IPv4 Flowspec component types to their new funcs
var FlowNewFuncs4 = map[FlowType]FlowNewFunc{
	FLOW_SRC:       NewFlowPrefix4,
	FLOW_DST:       NewFlowPrefix4,
	FLOW_PROTO:     NewFlowGeneric,
	FLOW_PORT:      NewFlowGeneric,
	FLOW_PORT_DST:  NewFlowGeneric,
	FLOW_PORT_SRC:  NewFlowGeneric,
	FLOW_ICMP_TYPE: NewFlowGeneric,
	FLOW_ICMP_CODE: NewFlowGeneric,
	FLOW_TCP_FLAGS: NewFlowGeneric,
	FLOW_PKTLEN:    NewFlowGeneric,
	FLOW_DSCP:      NewFlowGeneric,
	FLOW_FRAG:      NewFlowGeneric,
}

// FlowNewFuncs6 maps IPv6 Flowspec component types to their new funcs
var FlowNewFuncs6 = map[FlowType]FlowNewFunc{
	FLOW_SRC:       NewFlowPrefix6,
	FLOW_DST:       NewFlowPrefix6,
	FLOW_PROTO:     NewFlowGeneric,
	FLOW_PORT:      NewFlowGeneric,
	FLOW_PORT_DST:  NewFlowGeneric,
	FLOW_PORT_SRC:  NewFlowGeneric,
	FLOW_ICMP_TYPE: NewFlowGeneric,
	FLOW_ICMP_CODE: NewFlowGeneric,
	FLOW_TCP_FLAGS: NewFlowGeneric,
	FLOW_PKTLEN:    NewFlowGeneric,
	FLOW_DSCP:      NewFlowGeneric,
	FLOW_FRAG:      NewFlowGeneric,
	FLOW_LABEL:     NewFlowGeneric,
}

// NewFlowValue returns a new FlowValue for given FlowType and AFI
func NewFlowValue(ft FlowType, afi af.AFI) FlowValue {
	var newfuncs map[FlowType]FlowNewFunc
	if afi == af.AFI_IPV6 {
		newfuncs = FlowNewFuncs6
	} else {
		newfuncs = FlowNewFuncs4
	}

	newfunc, ok := newfuncs[ft]
	if !ok {
		newfunc = NewFlowRaw
	}

	return newfunc(ft)
}

// FlowOp represents a Flowspec operator (numeric or bitmask)
type FlowOp uint16

const (
	FLOW_OP_IS_BITMASK FlowOp = 0x0100

	FLOW_OP_LAST FlowOp = 0b10000000
	FLOW_OP_AND  FlowOp = 0b01000000
	FLOW_OP_LEN  FlowOp = 0b00110000

	FLOW_OP_NUM FlowOp = 0b00000111 // numeric
	FLOW_OP_LT  FlowOp = 0b00000100 // numeric
	FLOW_OP_GT  FlowOp = 0b00000010 // numeric
	FLOW_OP_EQ  FlowOp = 0b00000001 // numeric

	FLOW_OP_BIT   FlowOp = 0b00000011 // bitmask
	FLOW_OP_NOT   FlowOp = 0b00000010 // bitmask
	FLOW_OP_MATCH FlowOp = 0b00000001 // bitmask
)

// Len returns the length of the corresponding value: either 1, 2, 4, or 8
func (op FlowOp) Len() int {
	lcode := op & FLOW_OP_LEN
	return 1 << (lcode >> 4)
}

func (a *MPFlowspec) Unmarshal(cps caps.Caps) error {
	// best-effort NH parser
	if len(a.NH) > 0 {
		a.NextHop, a.LinkLocal, _ = ParseNH(a.NH)
	}

	data := a.Data
	for len(data) > 0 {
		l := int(data[0])
		if l >= 0xf0 && len(data) > 1 {
			l = (l & 0x0f) << 8
			l |= int(data[1])
			data = data[2:]
		} else {
			data = data[1:]
		}

		if len(data) < l {
			return ErrLength
		}
		val := data[:l]
		data = data[l:]

		rule := make(FlowRule)
		for len(val) > 0 {
			ft := FlowType(val[0])
			val = val[1:] // eat the type

			// create and parse FlowValue
			fv := NewFlowValue(ft, a.Afi())
			n, err := fv.Unmarshal(val, cps)
			if err != nil {
				return err
			}

			// store, move on
			rule[ft] = fv
			n = min(n, len(val))
			val = val[n:]
		}

		if len(rule) > 0 {
			a.Rules = append(a.Rules, rule)
		}
	}

	return nil
}

func (a *MPFlowspec) Marshal(cps caps.Caps) {
	// best-effort
	nh := a.NH[:0]
	if a.NextHop.IsValid() {
		nh = append(nh, a.NextHop.AsSlice()...)
		if a.LinkLocal.IsValid() {
			nh = append(nh, a.LinkLocal.AsSlice()...)
		}
	}
	a.NH = nh

	// write ar.Data using RFC8955/4
	var buf []byte
	data := a.Data[:0]
	for _, fr := range a.Rules {
		if len(fr) == 0 {
			continue
		}
		buf = fr.Marshal(buf[:0], cps)
		if bl := len(buf); bl < 0xf0 {
			data = append(data, byte(bl))
		} else {
			bl |= 0xf000
			data = msb.AppendUint16(data, uint16(bl))
		}
		data = append(data, buf...)
	}
	a.Data = data
}

func (a *MPFlowspec) ToJSON(dst []byte) []byte {
	if a.Code() == ATTR_MP_REACH && a.NextHop.IsValid() {
		dst = append(dst, `"nexthop":"`...)
		dst = a.NextHop.AppendTo(dst)
		if a.LinkLocal.IsValid() {
			dst = append(dst, `","link-local":"`...)
			dst = a.LinkLocal.AppendTo(dst)
		}
		dst = append(dst, `",`...)
	}

	dst = append(dst, `"rules":[`...)
	for i := range a.Rules {
		if i > 0 {
			dst = append(dst, `,`...)
		}
		dst = a.Rules[i].ToJSON(dst)
	}
	return append(dst, ']')
}

func (a *MPFlowspec) FromJSON(src []byte) error {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) (err error) {
		switch key {
		case "nexthop":
			if a.Code() == ATTR_MP_REACH {
				a.NextHop, err = netip.ParseAddr(json.S(val))
			}
		case "link-local":
			if a.Code() == ATTR_MP_REACH {
				a.LinkLocal, err = netip.ParseAddr(json.S(val))
			}
		case "rules":
			return json.ArrayEach(val, func(key int, val []byte, typ json.Type) error {
				rule := make(FlowRule)
				err := rule.FromJSON(val, a.Afi())
				if err != nil {
					return err
				}
				if len(rule) > 0 {
					a.Rules = append(a.Rules, rule)
				}
				return nil
			})
		}
		return err
	})
}

// Marshal writes wire representation of all components in fr to dst, without the length
func (fr FlowRule) Marshal(dst []byte, cps caps.Caps) []byte {
	var todo []FlowType
	for ft := range fr {
		todo = append(todo, ft)
	}
	sort.SliceStable(todo, func(i, j int) bool {
		return todo[i] < todo[j]
	})

	for _, ft := range todo {
		dst = append(dst, byte(ft))
		dst = fr[ft].Marshal(dst, cps)
	}
	return dst
}

func (fr FlowRule) ToJSON(dst []byte) []byte {
	dst = append(dst, '{')

	// respect the strict flowtype order
	var ftypes []FlowType
	for ft := range fr {
		ftypes = append(ftypes, ft)
	}
	sort.SliceStable(ftypes, func(i, j int) bool {
		return ftypes[i] < ftypes[j]
	})

	for i, ft := range ftypes {
		if i > 0 {
			dst = append(dst, `,"`...)
		} else {
			dst = append(dst, '"')
		}
		dst = append(dst, ft.String()...)
		dst = append(dst, `":`...)
		dst = fr[ft].ToJSON(dst)
	}

	return append(dst, '}')
}

func (fr FlowRule) FromJSON(src []byte, afi af.AFI) error {
	return json.ObjectEach(src, func(key string, val []byte, typ json.Type) error {
		// lookup flow type
		ftype, ok := FlowTypeValue[key]
		if !ok {
			return ErrFlowType
		}

		// create and read json
		fval := NewFlowValue(ftype, afi)
		err := fval.FromJSON(val)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrFlowValue, err)
		}

		// store
		fr[ftype] = fval
		return nil
	})
}

// ------------------

// FlowRaw represents a Flowspec component as raw bytes
type FlowRaw struct{ Raw []byte }

func NewFlowRaw(FlowType) FlowValue {
	return &FlowRaw{}
}

func (f *FlowRaw) Unmarshal(src []byte, cps caps.Caps) (int, error) {
	f.Raw = src
	return len(src), nil
}

func (f *FlowRaw) Marshal(dst []byte, cps caps.Caps) []byte {
	return append(dst, f.Raw...)
}

func (f *FlowRaw) ToJSON(dst []byte) []byte {
	return json.Hex(dst, f.Raw)
}

func (f *FlowRaw) FromJSON(src []byte) (err error) {
	f.Raw, err = json.UnHex(src, f.Raw[:0])
	return err
}

// FlowPrefix4 holds IPv4 prefix
type FlowPrefix4 struct{ netip.Prefix }

func NewFlowPrefix4(_ FlowType) FlowValue {
	return &FlowPrefix4{}
}

func (f *FlowPrefix4) Unmarshal(buf []byte, cps caps.Caps) (int, error) {
	if len(buf) < 1 {
		return 0, ErrLength
	}

	l := int(buf[0])
	if l > 32 {
		return 0, ErrValue
	}
	n := 1
	buf = buf[1:]

	b := l / 8
	if l%8 != 0 {
		b++
	}
	if len(buf) < b {
		return 0, ErrLength
	}

	var tmp [4]byte
	n += copy(tmp[:], buf[:b]) // the rest of [4]tmp is zeroed
	pfx, err := netip.AddrFrom4(tmp).Prefix(l)
	if err != nil {
		return 0, err
	}

	f.Prefix = pfx
	return n, nil
}

func (f *FlowPrefix4) Marshal(dst []byte, cps caps.Caps) []byte {
	return WritePrefix(dst, f.Prefix)
}

func (f *FlowPrefix4) ToJSON(dst []byte) []byte {
	return json.Prefix(dst, f.Prefix)
}

func (f *FlowPrefix4) FromJSON(src []byte) (err error) {
	f.Prefix, err = json.UnPrefix(src)
	return err
}

// FlowPrefix6 holds IPv6 prefix and offset
type FlowPrefix6 struct {
	Prefix netip.Prefix
	Offset int
}

func NewFlowPrefix6(_ FlowType) FlowValue {
	return &FlowPrefix6{}
}

func (f *FlowPrefix6) Unmarshal(buf []byte, cps caps.Caps) (int, error) {
	if len(buf) < 2 {
		return 0, ErrLength
	}

	l := int(buf[0])
	o := int(buf[1])
	if l > 128 || (o > 0 && o >= l) {
		return 0, ErrValue
	}
	n := 2
	buf = buf[n:]

	b := (l - o) / 8
	if (l-o)%8 != 0 {
		b++
	}
	if len(buf) < b {
		return 0, ErrLength
	}

	var tmp [16]byte
	n += copy(tmp[o/8:], buf[:b]) // the rest of [16]tmp is zeroed

	// offset%8 is 1-7?
	if r := o % 8; r != 0 && n > 0 {
		for i := (o / 8) + n - 1; i > o/8; i-- {
			tmp[i] = tmp[i]>>r | tmp[i-1]<<(8-r)
		}
		tmp[o/8] >>= r
	}

	pfx, err := netip.AddrFrom16(tmp).Prefix(l)
	if err != nil {
		return 0, err
	}

	f.Prefix = pfx
	f.Offset = o
	return n, nil
}

func (f *FlowPrefix6) Marshal(dst []byte, cps caps.Caps) []byte {
	// cut beyond prefix bits
	l := f.Prefix.Bits()
	b := l / 8
	if l%8 != 0 {
		b++
	}
	addr := f.Prefix.Addr().AsSlice()[:b]

	// cut before offset
	o := f.Offset
	addr = addr[o/8:]

	// offset%8 is 1-7?
	if r := o % 8; r != 0 {
		for i := 0; i < len(addr)-1; i++ {
			addr[i] = addr[i]<<r | addr[i+1]>>(8-r)
		}
		addr[len(addr)-1] <<= r
	}

	dst = append(dst, byte(l), byte(o))
	return append(dst, addr...)
}

// ToJSON encodes f as JSON.
// It writes "ipv6address/offset-length", if offset>0.
// Otherwise, just an ordinary prefix.
func (f *FlowPrefix6) ToJSON(dst []byte) []byte {
	if f.Offset == 0 {
		return json.Prefix(dst, f.Prefix)
	}
	dst = append(dst, '"')
	dst = f.Prefix.Addr().AppendTo(dst)
	dst = append(dst, '/')
	dst = strconv.AppendInt(dst, int64(f.Offset), 10)
	dst = append(dst, '-')
	dst = strconv.AppendInt(dst, int64(f.Prefix.Bits()), 10)
	return append(dst, '"')
}

func (f *FlowPrefix6) FromJSON(src []byte) (err error) {
	if bytes.IndexByte(src, '-') < 0 {
		f.Prefix, err = json.UnPrefix(src)
		return err
	}

	// split
	srcip, srcol, ok := strings.Cut(json.SQ(src), "/")
	if !ok {
		return ErrValue
	}

	// ipaddr/
	ip, err := netip.ParseAddr(srcip)
	if err != nil {
		return err
	}

	// offset-length
	srco, srcl, ok := strings.Cut(srcol, "-")
	if !ok {
		return ErrValue
	}
	o, err := strconv.Atoi(srco)
	if err != nil {
		return err
	}
	l, err := strconv.Atoi(srcl)
	if err != nil {
		return err
	}

	// looks sane?
	if l >= 0 && l <= 128 && o >= 0 && (o == 0 || o < l) {
		f.Prefix = netip.PrefixFrom(ip, l)
		f.Offset = o
		return nil
	}

	// no
	return ErrValue
}

// FlowGeneric represents a generic flowtype with a list of (operator, value) pairs
type FlowGeneric struct {
	Type FlowType
	Op   []FlowOp
	Val  []uint64
}

func NewFlowGeneric(ft FlowType) FlowValue {
	return &FlowGeneric{
		Type: ft,
	}
}

func (fv *FlowGeneric) Unmarshal(buf []byte, cps caps.Caps) (int, error) {
	n := 0
	for len(buf) > 0 {
		if len(buf) < 2 {
			return 0, ErrLength
		}

		// operator
		op := FlowOp(buf[0])
		buf = buf[1:]
		n += 1
		switch fv.Type {
		case FLOW_TCP_FLAGS, FLOW_FRAG: // the only bitmask_op values
			op |= FLOW_OP_IS_BITMASK
		}

		// value
		vlen := op.Len()
		if len(buf) < vlen {
			return 0, ErrLength
		}
		valb := buf[:vlen]
		buf = buf[vlen:]
		n += vlen

		// read valb into uint64
		var val uint64
		switch len(valb) {
		case 1:
			val = uint64(valb[0])
		case 2:
			val = uint64(msb.Uint16(valb))
		case 4:
			val = uint64(msb.Uint32(valb))
		case 8:
			val = uint64(msb.Uint64(valb))
		}

		// store
		fv.Op = append(fv.Op, op)
		fv.Val = append(fv.Val, val)

		// end-of-list marker?
		if op&FLOW_OP_LAST != 0 {
			break
		}
	}

	return n, nil
}

func (f *FlowGeneric) Marshal(dst []byte, cps caps.Caps) []byte {
	last := len(f.Op) - 1
	for i := range f.Op {
		op := f.Op[i]
		val := f.Val[i]

		if i == last {
			op |= FLOW_OP_LAST
		} else {
			op &= ^FLOW_OP_LAST
		}
		dst = append(dst, byte(op))

		switch op.Len() {
		case 1:
			dst = append(dst, byte(val))
		case 2:
			dst = msb.AppendUint16(dst, uint16(val))
		case 4:
			dst = msb.AppendUint32(dst, uint32(val))
		case 8:
			dst = msb.AppendUint64(dst, val)
		}

		if i == last {
			break
		}
	}
	return dst
}

func (f *FlowGeneric) ToJSON(dst []byte) []byte {
	dst = append(dst, '[')
	for i := range f.Op {
		op := f.Op[i]
		val := f.Val[i]

		if i > 0 {
			dst = append(dst, `,{`...)
		} else {
			dst = append(dst, `{`...)
		}

		if op&FLOW_OP_AND != 0 {
			dst = append(dst, `"and":true,`...)
		}
		dst = append(dst, `"op":`...)
		if op&FLOW_OP_IS_BITMASK == 0 {
			switch op & FLOW_OP_NUM {
			case 0b000:
				dst = append(dst, `false`...)
			case 0b001:
				dst = append(dst, `"=="`...)
			case 0b010:
				dst = append(dst, `">"`...)
			case 0b011:
				dst = append(dst, `">="`...)
			case 0b100:
				dst = append(dst, `"<"`...)
			case 0b101:
				dst = append(dst, `"<="`...)
			case 0b110:
				dst = append(dst, `"!="`...)
			case 0b111:
				dst = append(dst, `true`...)
			}

			dst = append(dst, `,"val":`...)
			dst = strconv.AppendUint(dst, val, 10)

		} else {
			switch op & FLOW_OP_BIT {
			case 0b00:
				dst = append(dst, `"ANY"`...)
			case 0b01:
				dst = append(dst, `"ALL"`...)
			case 0b10:
				dst = append(dst, `"NONE"`...)
			case 0b11:
				dst = append(dst, `"NOT-ALL"`...)
			}

			dst = append(dst, `,"len":`...)
			dst = strconv.AppendUint(dst, uint64(op.Len()), 10)

			dst = append(dst, `,"val":`...)
			dst = append(dst, `"0x`...)
			dst = strconv.AppendUint(dst, val, 16)
			dst = append(dst, `"`...)
		}

		dst = append(dst, `}`...)
	}
	dst = append(dst, ']')
	return dst
}

func (f *FlowGeneric) FromJSON(src []byte) (err error) {
	f.Op = f.Op[:0]
	f.Val = f.Val[:0]
	return json.ArrayEach(src, func(key int, val []byte, typ json.Type) error {
		// parse op+val definition
		var fop FlowOp
		var fval uint64
		err := json.ObjectEach(val, func(key string, val []byte, typ json.Type) error {
			switch key {
			case "and":
				and, err := json.UnBool(val)
				if err != nil {
					return err
				}
				if and {
					fop |= FLOW_OP_AND
				}

			case "op":
				switch json.SQ(val) {
				case "false", "FALSE":
					fop |= 0b000
				case "==":
					fop |= 0b001
				case ">":
					fop |= 0b010
				case ">=":
					fop |= 0b011
				case "<":
					fop |= 0b100
				case "<=":
					fop |= 0b101
				case "!=":
					fop |= 0b110
				case "true", "TRUE":
					fop |= 0b111
				case "ANY", "any":
					fop |= FLOW_OP_IS_BITMASK
				case "ALL", "all":
					fop |= FLOW_OP_IS_BITMASK | 0b01
				case "NONE", "none":
					fop |= FLOW_OP_IS_BITMASK | 0b10
				case "NOT-ALL", "not-all":
					fop |= FLOW_OP_IS_BITMASK | 0b11
				default:
					return ErrValue
				}

			case "val":
				val, err := strconv.ParseUint(json.SQ(val), 0, 64)
				if err != nil {
					return err
				}
				fval = val

			case "len":
				l, err := strconv.ParseUint(json.SQ(val), 10, 64)
				if err != nil {
					return err
				}
				switch l {
				case 1:
					fop |= 0b00 << 4
				case 2:
					fop |= 0b01 << 4
				case 4:
					fop |= 0b10 << 4
				case 8:
					fop |= 0b11 << 4
				default:
					return ErrValue
				}

			default:
				return ErrValue
			}

			return nil
		})
		if err != nil {
			return err
		}

		// add to f, iterate to next (operator, value) element
		f.Op = append(f.Op, fop)
		f.Val = append(f.Val, fval)
		return nil
	})
}
