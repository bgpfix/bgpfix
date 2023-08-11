package msg

import (
	"net/netip"
	"sort"
	"strconv"
)

// ATTR_MP_* for RFC8955 and RFC8956 Flowspec
type AttrMPFlow struct {
	*AttrMP

	NextHop   netip.Addr // best-effort
	LinkLocal netip.Addr // best-effort
	Rules     []FlowRule // see RFC8955 Fig1
}

// FlowRule represents a collection of flowspec components
type FlowRule map[FlowType]FlowComp

// FlowType represent Flowspec component type
type FlowType uint8

// FlowComp represents the value of a particular Flowspec component
type FlowComp interface {
	// Marshal appends wire representation to dst, without type
	Marshal(dst []byte, caps Caps) []byte

	// ToJSON appends JSON representation of the component to dst
	ToJSON(dst []byte) []byte
}

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

// FlowParser parses specific Flowspec component type inside given Flowspec rule
type FlowParser func(ft FlowType, buf []byte) (FlowComp, int, error)

// FlowParsers4 maps IPv4 Flowspec component types to their parsers
var FlowParsers4 = map[FlowType]FlowParser{
	FLOW_SRC:       ParseFlowPrefix4,
	FLOW_DST:       ParseFlowPrefix4,
	FLOW_PROTO:     ParseFlowVal,
	FLOW_PORT:      ParseFlowVal,
	FLOW_PORT_DST:  ParseFlowVal,
	FLOW_PORT_SRC:  ParseFlowVal,
	FLOW_ICMP_TYPE: ParseFlowVal,
	FLOW_ICMP_CODE: ParseFlowVal,
	FLOW_TCP_FLAGS: ParseFlowVal,
	FLOW_PKTLEN:    ParseFlowVal,
	FLOW_DSCP:      ParseFlowVal,
	FLOW_FRAG:      ParseFlowVal,
}

// FlowParsers6 maps IPv6 Flowspec component types to their parsers
var FlowParsers6 = map[FlowType]FlowParser{
	FLOW_SRC:       ParseFlowPrefix6,
	FLOW_DST:       ParseFlowPrefix6,
	FLOW_PROTO:     ParseFlowVal,
	FLOW_PORT:      ParseFlowVal,
	FLOW_PORT_DST:  ParseFlowVal,
	FLOW_PORT_SRC:  ParseFlowVal,
	FLOW_ICMP_TYPE: ParseFlowVal,
	FLOW_ICMP_CODE: ParseFlowVal,
	FLOW_TCP_FLAGS: ParseFlowVal,
	FLOW_PKTLEN:    ParseFlowVal,
	FLOW_DSCP:      ParseFlowVal,
	FLOW_FRAG:      ParseFlowVal,
	FLOW_LABEL:     ParseFlowVal,
}

func NewParseAttrMPFlow(mp *AttrMP) AttrMPValue {
	return &AttrMPFlow{AttrMP: mp}
}

func (a *AttrMPFlow) Unmarshal(_ Caps) error {
	var (
		ipv6 = a.Afi() == AFI_IPV6
		comp FlowComp
		err  error
	)

	// best-effort NH parser
	if len(a.NH) > 0 {
		a.NextHop, a.LinkLocal, _ = parseNH(a.NH)
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

			// the default
			comp = FlowRaw(val)
			n := len(val)

			if ipv6 {
				if cb := FlowParsers6[ft]; cb != nil {
					comp, n, err = cb(ft, val)
				}
			} else {
				if cb := FlowParsers4[ft]; cb != nil {
					comp, n, err = cb(ft, val)
				}
			}

			if err != nil {
				return err
			}

			rule[ft] = comp
			val = val[n:]
		}

		if len(rule) > 0 {
			a.Rules = append(a.Rules, rule)
		}
	}

	return nil
}

func (a *AttrMPFlow) Marshal(caps Caps) {
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
		buf = fr.Marshal(buf[:0], caps)
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

func (a *AttrMPFlow) ToJSON(dst []byte) []byte {
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

func (a *AttrMPFlow) FromJSON(src []byte) error {
	return ErrTODO
}

// Marshal writes wire representation of all components in fr to dst, without the length
func (fr FlowRule) Marshal(dst []byte, caps Caps) []byte {
	var todo []FlowType
	for ft := range fr {
		todo = append(todo, ft)
	}
	sort.SliceStable(todo, func(i, j int) bool {
		return todo[i] < todo[j]
	})

	for _, ft := range todo {
		dst = append(dst, byte(ft))
		dst = fr[ft].Marshal(dst, caps)
	}
	return dst
}

func (fr FlowRule) ToJSON(dst []byte) []byte {
	dst = append(dst, '{')

	// respect the strict flowtype order
	var todo []FlowType
	for ft := range fr {
		todo = append(todo, ft)
	}
	sort.SliceStable(todo, func(i, j int) bool {
		return todo[i] < todo[j]
	})

	for i, ft := range todo {
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

// ------------------

// FlowRaw represents a Flowspec component as raw bytes
type FlowRaw []byte

func (f FlowRaw) Marshal(dst []byte, caps Caps) []byte {
	return append(dst, f...)
}

func (f FlowRaw) ToJSON(dst []byte) []byte {
	return jsonHex(dst, f)
}

// FlowPrefix4 holds IPv4 prefix
type FlowPrefix4 struct{ netip.Prefix }

func ParseFlowPrefix4(ft FlowType, buf []byte) (FlowComp, int, error) {
	if len(buf) < 1 {
		return nil, 0, ErrLength
	}

	l := int(buf[0])
	buf = buf[1:]
	if l > 32 {
		return nil, 0, ErrValue
	}

	b := l / 8
	if l%8 != 0 {
		b++
	}
	if len(buf) < b {
		return nil, 0, ErrLength
	}

	var tmp [4]byte
	n := copy(tmp[:], buf[:b]) // the rest of [4]tmp is zeroed
	pfx, err := netip.AddrFrom4(tmp).Prefix(l)
	if err != nil {
		return nil, 0, err
	}

	return &FlowPrefix4{pfx}, n + 1, nil
}

func (f *FlowPrefix4) Marshal(dst []byte, caps Caps) []byte {
	return marshalPrefix(dst, f.Prefix)
}

func (f *FlowPrefix4) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = f.AppendTo(dst)
	return append(dst, '"')
}

// AddSrc adds FLOW_SRC match to rule fr
func (fr FlowRule) AddSrc(p netip.Prefix) {
	fr[FLOW_SRC] = &FlowPrefix4{p}
}

// AddDst adds FLOW_DST match to rule fr
func (fr FlowRule) AddDst(p netip.Prefix) {
	fr[FLOW_DST] = &FlowPrefix4{p}
}

// FlowPrefix6 holds IPv6 prefix and offset
type FlowPrefix6 struct {
	Prefix netip.Prefix
	Offset int
}

func ParseFlowPrefix6(ft FlowType, buf []byte) (FlowComp, int, error) {
	if len(buf) < 2 {
		return nil, 0, ErrLength
	}

	l := int(buf[0])
	o := int(buf[1])
	buf = buf[2:]
	if l > 128 || (o > 0 && o >= l) {
		return nil, 0, ErrValue
	}

	b := (l - o) / 8
	if (l-o)%8 != 0 {
		b++
	}
	if len(buf) < b {
		return nil, 0, ErrLength
	}

	var tmp [16]byte
	n := copy(tmp[o/8:], buf[:b]) // the rest of [16]tmp is zeroed

	// offset%8 is 1-7?
	if r := o % 8; r != 0 && n > 0 {
		for i := (o / 8) + n - 1; i > o/8; i-- {
			tmp[i] = tmp[i]>>r | tmp[i-1]<<(8-r)
		}
		tmp[o/8] >>= r
	}

	pfx, err := netip.AddrFrom16(tmp).Prefix(l)
	if err != nil {
		return nil, 0, err
	}

	return &FlowPrefix6{pfx, o}, n + 2, nil
}

func (f *FlowPrefix6) Marshal(dst []byte, caps Caps) []byte {
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

// ipv6address/offset-length if offset>0
func (f *FlowPrefix6) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = f.Prefix.Addr().AppendTo(dst)
	dst = append(dst, '/')
	if f.Offset > 0 {
		dst = strconv.AppendInt(dst, int64(f.Offset), 10)
		dst = append(dst, '-')
	}
	dst = strconv.AppendInt(dst, int64(f.Prefix.Bits()), 10)
	return append(dst, '"')
}

// FlowVal represents a list of operator + value pairs
type FlowVal struct {
	Op  []FlowOp
	Val []uint64
}

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

func ParseFlowVal(ft FlowType, buf []byte) (comp FlowComp, n int, err error) {
	fv := &FlowVal{}
	for len(buf) > 0 {
		if len(buf) < 2 {
			return nil, 0, ErrLength
		}

		// operator
		op := FlowOp(buf[0])
		buf = buf[1:]
		n += 1
		switch ft {
		case FLOW_TCP_FLAGS, FLOW_FRAG: // the only bitmask_op values
			op |= FLOW_OP_IS_BITMASK
		}

		// value
		vlen := op.Len()
		if len(buf) < vlen {
			return nil, 0, ErrLength
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

	return fv, n, nil
}

func (f *FlowVal) Marshal(dst []byte, caps Caps) []byte {
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

func (f *FlowVal) ToJSON(dst []byte) []byte {
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
			dst = strconv.AppendUint(dst, uint64(val), 10)

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
			dst = strconv.AppendInt(dst, int64(op.Len()), 10)

			dst = append(dst, `"`...)
			dst = strconv.AppendUint(dst, uint64(val), 16)
			dst = append(dst, `"`...)
		}

		dst = append(dst, `}`...)
	}
	dst = append(dst, ']')
	return dst
}
