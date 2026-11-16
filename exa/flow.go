package exa

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/nlri"
)

// flowKeys maps ExaBGP flow match keywords to Flowspec component types
var flowKeys = map[string]attrs.FlowType{
	"destination":      attrs.FLOW_DST,
	"destination-ipv4": attrs.FLOW_DST,
	"destination-ipv6": attrs.FLOW_DST,
	"source":           attrs.FLOW_SRC,
	"source-ipv4":      attrs.FLOW_SRC,
	"source-ipv6":      attrs.FLOW_SRC,
	"protocol":         attrs.FLOW_PROTO,
	"next-header":      attrs.FLOW_PROTO, // IPv6
	"port":             attrs.FLOW_PORT,
	"destination-port": attrs.FLOW_PORT_DST,
	"source-port":      attrs.FLOW_PORT_SRC,
	"icmp-type":        attrs.FLOW_ICMP_TYPE,
	"icmp-code":        attrs.FLOW_ICMP_CODE,
	"tcp-flags":        attrs.FLOW_TCP_FLAGS,
	"packet-length":    attrs.FLOW_PKTLEN,
	"dscp":             attrs.FLOW_DSCP,
	"traffic-class":    attrs.FLOW_DSCP, // IPv6
	"fragment":         attrs.FLOW_FRAG,
	"flow-label":       attrs.FLOW_LABEL, // IPv6
}

// flowNames lists the keywords we write, by component type, for IPv4 and IPv6
var flowNames = [14][2]string{
	attrs.FLOW_DST:       {"destination", "destination"},
	attrs.FLOW_SRC:       {"source", "source"},
	attrs.FLOW_PROTO:     {"protocol", "next-header"},
	attrs.FLOW_PORT:      {"port", "port"},
	attrs.FLOW_PORT_DST:  {"destination-port", "destination-port"},
	attrs.FLOW_PORT_SRC:  {"source-port", "source-port"},
	attrs.FLOW_ICMP_TYPE: {"icmp-type", "icmp-type"},
	attrs.FLOW_ICMP_CODE: {"icmp-code", "icmp-code"},
	attrs.FLOW_TCP_FLAGS: {"tcp-flags", "tcp-flags"},
	attrs.FLOW_PKTLEN:    {"packet-length", "packet-length"},
	attrs.FLOW_DSCP:      {"dscp", "traffic-class"},
	attrs.FLOW_FRAG:      {"fragment", "fragment"},
	attrs.FLOW_LABEL:     {"flow-label", "flow-label"},
}

// flowValues maps the value names that ExaBGP knows to numbers
// NB: one map for all component types, the names do not collide
var flowValues = map[string]uint64{
	// protocol
	"icmp": 1, "igmp": 2, "tcp": 6, "egp": 8, "udp": 17, "rsvp": 46,
	"gre": 47, "esp": 50, "ah": 51, "ospf": 89, "pim": 103, "sctp": 132,
	// tcp-flags
	"fin": 0x01, "syn": 0x02, "rst": 0x04, "push": 0x08, "ack": 0x10,
	"urg": 0x20, "urgent": 0x20, "ece": 0x40, "cwr": 0x80,
	// fragment
	"dont-fragment": 0x01, "is-fragment": 0x02, "first-fragment": 0x04, "last-fragment": 0x08,
	// icmp-type
	"echo-reply": 0, "unreachable": 3, "redirect": 5, "echo-request": 8, "time-exceeded": 11,
}

// flow actions: types of extended communities
const (
	flowRateBytes   = uint64(attrs.EXTCOM_FLOW_RATE_BYTES)
	flowRatePackets = uint64(attrs.EXTCOM_FLOW_RATE_PACKETS)
	flowAction      = uint64(attrs.EXTCOM_FLOW_ACTION)
	flowRedirectAS2 = uint64(attrs.EXTCOM_FLOW_REDIRECT_AS2)
	flowRedirectAS4 = uint64(attrs.EXTCOM_FLOW_REDIRECT_AS4)
	flowRedirectNH  = uint64(attrs.EXTCOM_FLOW_REDIRECT_NH)
	flowMark        = uint64(attrs.EXTCOM_FLOW_DSCP)
)

// parseFlow parses what follows announce|withdraw flow route: match components into x.Flow,
// actions into x.ExtCommunity. Takes both { match { ...; } then { ...; } } and the flat form.
func (x *Exa) parseFlow(tok []string) error {
	// act adds the action, as an extended community
	act := func(typ, val uint64) {
		x.ExtCommunity = append(x.ExtCommunity, fmt.Sprintf("0x%016x", typ<<48|val))
	}

	for len(tok) > 0 {
		var key string
		key, tok = tok[0], tok[1:]

		// syntax, and keywords with no value
		switch key {
		case "{", "}", ";", "match", "then", "accept":
			continue
		case "discard":
			act(flowRateBytes, 0)
			continue
		case "redirect-to-nexthop":
			act(flowRedirectNH, 0)
			continue
		}

		vals, n := parseList(tok)
		if len(vals) == 0 {
			return ErrMissingValue
		}
		tok = tok[n:]
		v := vals[0]

		// a match component?
		if _, ok := flowKeys[key]; ok {
			x.Flow = append(x.Flow, key+" "+strings.Join(vals, " "))
			continue
		}

		// an action, or an attribute
		switch key {
		case "rate-limit": // rate-limit <n> [bytes|packets]
			rate, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return ErrInvalidValue
			}
			typ := flowRateBytes
			if len(tok) > 0 && (tok[0] == "bytes" || tok[0] == "packets") {
				if tok[0] == "packets" {
					typ = flowRatePackets
				}
				tok = tok[1:]
			}
			act(typ, uint64(math.Float32bits(float32(rate))))
		case "redirect": // redirect <asn>:<number>, or to an IP address (next-hop)
			if _, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
				x.NextHop = strings.Trim(v, "[]")
				act(flowRedirectNH, 0)
				break
			}
			as, num, _ := strings.Cut(v, ":")
			asn, err1 := strconv.ParseUint(as, 10, 32)
			n, err2 := strconv.ParseUint(num, 10, 32)
			if err1 != nil || err2 != nil || (asn > 0xffff && n > 0xffff) {
				return ErrInvalidValue
			} else if asn > 0xffff {
				act(flowRedirectAS4, asn<<16|n)
			} else {
				act(flowRedirectAS2, asn<<32|n)
			}
		case "copy": // copy to an IP address (next-hop)
			x.NextHop = v
			act(flowRedirectNH, 1)
		case "mark":
			dscp, err := strconv.ParseUint(v, 10, 6)
			if err != nil {
				return ErrInvalidValue
			}
			act(flowMark, dscp)
		case "action": // sample, terminal, or sample-terminal
			var bits uint64
			if strings.Contains(v, "terminal") {
				bits |= 0x01
			}
			if strings.Contains(v, "sample") {
				bits |= 0x02
			}
			act(flowAction, bits)
		default:
			if err := x.parseAttr(key, vals); err != nil {
				return err
			}
		}
	}

	if len(x.Flow) == 0 {
		return ErrInvalidFormat // NB: would match all traffic
	}
	return nil
}

// flowString writes x as an ExaBGP flow route, in the flat form
func (x *Exa) flowString() string {
	x.Tok = append(x.Tok[:0], x.Action, "flow", "route")
	for _, c := range x.Flow {
		key, val, _ := strings.Cut(c, " ")
		if strings.Contains(val, " ") {
			val = "[ " + val + " ]" // many operands
		}
		x.Tok = append(x.Tok, key, val)
	}

	// actions
	var ext []string
	for _, c := range x.ExtCommunity {
		v, _ := strconv.ParseUint(strings.TrimPrefix(c, "0x"), 16, 64)
		val := v & 0xffffffffffff
		switch v >> 48 {
		case flowRateBytes, flowRatePackets:
			rate := math.Float32frombits(uint32(val))
			if val>>32 != 0 || float32(uint32(rate)) != rate {
				ext = append(ext, c) // NB: has an ASN, or is not a whole number: keep as is
			} else if v>>48 == flowRatePackets {
				x.Tok = append(x.Tok, "rate-limit", strconv.FormatUint(uint64(rate), 10), "packets")
			} else if rate == 0 {
				x.Tok = append(x.Tok, "discard")
			} else {
				x.Tok = append(x.Tok, "rate-limit", strconv.FormatUint(uint64(rate), 10))
			}
		case flowRedirectAS2:
			x.Tok = append(x.Tok, "redirect", fmt.Sprintf("%d:%d", uint16(val>>32), uint32(val)))
		case flowRedirectAS4:
			x.Tok = append(x.Tok, "redirect", fmt.Sprintf("%d:%d", uint32(val>>16), uint16(val)))
		case flowRedirectNH:
			if x.NextHop == "" {
				x.Tok = append(x.Tok, "redirect-to-nexthop")
			} else if val&1 != 0 {
				x.Tok = append(x.Tok, "copy", x.NextHop)
			} else {
				x.Tok = append(x.Tok, "redirect", x.NextHop)
			}
		case flowMark:
			x.Tok = append(x.Tok, "mark", strconv.FormatUint(val&0x3f, 10))
		case flowAction:
			if name := [4]string{"", "terminal", "sample", "sample-terminal"}[val&3]; name != "" {
				x.Tok = append(x.Tok, "action", name)
			} else {
				ext = append(ext, c)
			}
		default:
			ext = append(ext, c)
		}
	}

	// NB: ExaBGP takes no other attributes here
	if len(x.Community) > 0 {
		x.Tok = append(x.Tok, "community", formatCommunity(x.Community))
	}
	if len(x.LargeCommunity) > 0 {
		x.Tok = append(x.Tok, "large-community", formatCommunity(x.LargeCommunity))
	}
	if len(ext) > 0 {
		x.Tok = append(x.Tok, "extended-community", formatCommunity(ext))
	}

	x.Str = strings.Join(x.Tok, " ")
	return x.Str
}

// flowToMsg writes the flow rule in x.Flow to u, as IPv4 or IPv6 Flowspec
func (x *Exa) flowToMsg(u *msg.Update) error {
	// IPv6?
	as := afi.AS_IPV4_FLOWSPEC
	for _, c := range x.Flow {
		key, val, _ := strings.Cut(c, " ")
		switch key {
		case "next-header", "traffic-class", "flow-label", "destination-ipv6", "source-ipv6":
			as = afi.AS_IPV6_FLOWSPEC
		case "destination", "source":
			if strings.Contains(val, ":") {
				as = afi.AS_IPV6_FLOWSPEC
			}
		}
	}

	rule := make(attrs.FlowRule)
	for _, c := range x.Flow {
		key, val, _ := strings.Cut(c, " ")
		ft, ok := flowKeys[key]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnsupported, key)
		}

		var err error
		if ft > attrs.FLOW_SRC {
			rule[ft], err = parseFlowOps(ft, val)
		} else if as == afi.AS_IPV4_FLOWSPEC {
			var p netip.Prefix
			p, err = netip.ParsePrefix(val)
			if err == nil && !p.Addr().Is4() {
				err = ErrInvalidPrefix
			}
			rule[ft] = &attrs.FlowPrefix4{Prefix: nlri.FromPrefix(p)}
		} else { // IPv6: address/length[/offset]
			fp := &attrs.FlowPrefix6{}
			if i := strings.LastIndexByte(val, '/'); strings.Count(val, "/") == 2 {
				fp.Offset, err = strconv.Atoi(val[i+1:])
				val = val[:i]
			}
			if err == nil {
				fp.Prefix, err = netip.ParsePrefix(val)
			}
			if err == nil && (!fp.Prefix.Addr().Is6() || fp.Offset < 0 || fp.Offset > 0 && fp.Offset >= fp.Prefix.Bits()) {
				err = ErrInvalidPrefix
			}
			rule[ft] = fp
		}
		if err != nil {
			return fmt.Errorf("%s: %w", key, ErrInvalidValue)
		}
	}

	// add the rule
	code := attrs.ATTR_MP_REACH
	if x.Action == "withdraw" {
		code = attrs.ATTR_MP_UNREACH
	}
	mp := u.Attrs.Use(code).(*attrs.MP)
	mp.AS = as
	fs := attrs.NewMPFlowspec(mp).(*attrs.MPFlowspec)
	fs.Rules = append(fs.Rules, rule)
	mp.Value = fs
	if x.Action == "withdraw" {
		return nil
	}

	// redirect to next-hop?
	if x.NextHop != "" && x.NextHop != "self" {
		nh, err := netip.ParseAddr(x.NextHop)
		if err != nil {
			return ErrInvalidNextHop
		}
		fs.NextHop = nh
	}
	return x.writeAttrs(u)
}

// parseFlowOps parses the operators and values of a flow component,
// eg. "=80 =443", ">1024&<2048", "tcp", "syn !ack", "=syn+ack"
func parseFlowOps(ft attrs.FlowType, s string) (*attrs.FlowGeneric, error) {
	fg := &attrs.FlowGeneric{Type: ft}
	bitmask := ft == attrs.FLOW_TCP_FLAGS || ft == attrs.FLOW_FRAG

	for _, f := range strings.Fields(s) {
		for i, e := range strings.Split(f, "&") { // NB: & joins with the previous one
			var op attrs.FlowOp
			if i > 0 {
				op |= attrs.FLOW_OP_AND
			}

			// operator
			cut := func(prefix string, bits attrs.FlowOp) bool {
				if strings.HasPrefix(e, prefix) {
					e, op = e[len(prefix):], op|bits
					return true
				}
				return false
			}
			if bitmask {
				op |= attrs.FLOW_OP_IS_BITMASK
				_ = cut("!=", attrs.FLOW_OP_NOT|attrs.FLOW_OP_MATCH) || cut("=", attrs.FLOW_OP_MATCH) || cut("!", attrs.FLOW_OP_NOT)
			} else if !(cut(">=", attrs.FLOW_OP_GT|attrs.FLOW_OP_EQ) || cut("<=", attrs.FLOW_OP_LT|attrs.FLOW_OP_EQ) ||
				cut("!=", attrs.FLOW_OP_LT|attrs.FLOW_OP_GT) || cut(">", attrs.FLOW_OP_GT) || cut("<", attrs.FLOW_OP_LT) ||
				cut("true", attrs.FLOW_OP_NUM) || cut("false", 0) || cut("=", attrs.FLOW_OP_EQ)) {
				op |= attrs.FLOW_OP_EQ
			}

			// value: a number, a name, or names joined with +
			// NB: true and false take no value
			var val uint64
			if n := op & attrs.FLOW_OP_NUM; bitmask || e != "" || (n != 0 && n != attrs.FLOW_OP_NUM) {
				for _, name := range strings.Split(e, "+") {
					if v, ok := flowValues[name]; ok {
						val |= v
					} else if v, err := strconv.ParseUint(name, 0, 64); err == nil {
						val |= v
					} else {
						return nil, ErrInvalidValue
					}
				}
			}

			// value length
			switch {
			case val > 0xffffffff:
				op |= 3 << 4
			case val > 0xffff:
				op |= 2 << 4
			case val > 0xff:
				op |= 1 << 4
			}

			fg.Op = append(fg.Op, op)
			fg.Val = append(fg.Val, val)
		}
	}

	if len(fg.Op) == 0 {
		return nil, ErrMissingValue
	}
	return fg, nil
}

// readFlow sets x.Flow to the match components of rule
func (x *Exa) readFlow(rule attrs.FlowRule, v6 int) {
	types := make([]attrs.FlowType, 0, len(rule))
	for ft := range rule {
		types = append(types, ft)
	}
	slices.Sort(types)

	for _, ft := range types {
		if int(ft) >= len(flowNames) || flowNames[ft][v6] == "" {
			continue // unknown component type
		}
		s := flowNames[ft][v6]

		switch fv := rule[ft].(type) {
		case *attrs.FlowPrefix4:
			s += " " + fv.Prefix.String()
		case *attrs.FlowPrefix6:
			s += " " + fv.Prefix.String()
			if fv.Offset > 0 {
				s += "/" + strconv.Itoa(fv.Offset)
			}
		case *attrs.FlowGeneric:
			for i, op := range fv.Op {
				if op&attrs.FLOW_OP_AND != 0 && i > 0 {
					s += "&"
				} else {
					s += " "
				}
				if op&attrs.FLOW_OP_IS_BITMASK != 0 {
					s += [4]string{"", "=", "!", "!="}[op&attrs.FLOW_OP_BIT] + fmt.Sprintf("0x%x", fv.Val[i])
				} else if n := op & attrs.FLOW_OP_NUM; n == 0 || n == attrs.FLOW_OP_NUM {
					s += [8]string{0: "false", 7: "true"}[n]
				} else {
					s += [8]string{1: "=", 2: ">", 3: ">=", 4: "<", 5: "<=", 6: "!="}[n] + strconv.FormatUint(fv.Val[i], 10)
				}
			}
		default:
			continue
		}
		x.Flow = append(x.Flow, s)
	}
}
