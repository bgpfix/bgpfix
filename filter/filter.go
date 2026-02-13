package filter

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/msg"
)

// Filter represents a BGP message filter, compiled from a string representation.
type Filter struct {
	// raw filter string, eg:
	// !(UPDATE && (origin == 39282 || aspath[0] < 1000) && com ~ "11:22")
	String string

	// the first parsed expression in the filter
	First *Expr
}

// Expr represents an expression like <attribute> <operator> <value>,
// optionally linked with the next expression using a logical AND or OR.
type Expr struct {
	Filter *Filter // root filter, must be non-nil
	String string  // raw expression string
	Types  bool    // allow message types other than UPDATE?

	Not   bool // negate the final result of this expression?
	OpNot bool // operator-level negation (!=, !~): negate match only if attribute exists
	And   bool // apply logical AND with the next expression? (if false, apply OR)
	Next  *Expr // next expression (nil means last)

	Attr Attr // attribute
	Idx  any  // index inside the attribute (eg. int(0) if aspath[0])
	Op   Op   // operator
	Val  any  // value to use (string, int, regexp, etc OR *Expr if nested)
}

type (
	Attr = int
	Op   = int
)

const (
	ATTR_EXPR       Attr = iota // sub-expression in value (nested)
	ATTR_TAG                    // message tag (from pipe context)
	ATTR_TYPE                   // BGP message type
	ATTR_AF                     // address family / subsequent address family
	ATTR_REACH                  // reachable prefixes
	ATTR_UNREACH                // unreachable prefixes
	ATTR_PREFIX                 // prefix, either reachable or unreachable
	ATTR_ASPATH                 // AS_PATH attribute
	ATTR_ASPATH_LEN             // AS_PATH length
	ATTR_NEXTHOP                // NEXT_HOP attribute
	ATTR_ORIGIN                 // ORIGIN attribute (IGP/EGP/INCOMPLETE)
	ATTR_MED                    // MULTI_EXIT_DISC attribute
	ATTR_LOCALPREF              // LOCAL_PREF attribute
	ATTR_COMM                   // COMMUNITY attribute
	ATTR_COMM_EXT               // EXTENDED_COMMUNITY attribute
	ATTR_COMM_LARGE             // LARGE_COMMUNITY attribute
	ATTR_ASPATH_HOPS            // AS_PATH unique hop count (ignoring prepending)
	ATTR_OTC                    // OTC attribute (Only To Customer, RFC 9234)
	ATTR_DIR                    // message direction (L/R)
	ATTR_SEQ                    // message sequence number
	ATTR_TIME                   // message timestamp
	ATTR_JSON                   // generic JSON path extractor
	ATTR_JSONATTR               // attribute-specific JSON extractor
)

const (
	OP_TRUE Op = iota // is true? (no value)
	OP_EQ             // ==
	OP_LT             // <
	OP_LE             // <=
	OP_GT             // >
	OP_GE             // >=
	OP_LIKE           // ~ (match)
)

// cmpOp evaluates a three-way comparison result against an operator.
func cmpOp(cmp int, op Op) bool {
	switch op {
	case OP_EQ:
		return cmp == 0
	case OP_LT:
		return cmp < 0
	case OP_LE:
		return cmp <= 0
	case OP_GT:
		return cmp > 0
	case OP_GE:
		return cmp >= 0
	}
	return false
}

func NewFilter(filter string) (*Filter, error) {
	f := &Filter{
		String: filter,
	}

	// parse the filter string
	parsed, left, err := f.parse(filter, 0)
	if err != nil {
		if left != "" {
			return nil, fmt.Errorf("filter '%s': parse error near '%s': %w", filter, left, err)
		} else {
			return nil, fmt.Errorf("filter '%s': parse error: %w", filter, err)
		}
	}

	f.First = parsed
	return f, nil
}

func (f *Filter) parse(expstr string, lvl int) (parsed *Expr, left string, err error) {
	str := strings.TrimSpace(expstr)
	if len(str) == 0 {
		return nil, str, ErrEmpty
	}

	parsed = &Expr{String: str}
	exp := parsed
	for {
		// are we done?
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			break
		}

		// expect next expression?
		if exp.Filter != nil {
			switch {
			case str[0] == ')': // end of sub-expression
				if lvl > 0 {
					return parsed, str[1:], nil
				} else {
					return nil, str, ErrUnmatched // unexpected closing parenthesis
				}
			case strings.HasPrefix(str, "&&"):
				exp.And = true
				str = str[2:]
			case strings.HasPrefix(str, "||"):
				exp.And = false
				str = str[2:]
			default:
				return nil, str, ErrLogic
			}

			str = strings.TrimSpace(str)
			exp.Next = &Expr{String: str}
			exp = exp.Next
		}

		// negation or sub-expression?
		switch str[0] {
		case '!':
			str = str[1:]
			exp.Not = true
			continue

		case '(':
			str = str[1:]

			nexp, nstr, nerr := f.parse(str, lvl+1)
			if nerr != nil {
				if nstr != "" {
					str = nstr
				}
				return nil, str, nerr
			}

			exp.Attr = ATTR_EXPR
			exp.Val = nexp
			exp.Filter = f // ready for use
			str = nstr
			continue
		}

		// read attribute name
		var attr string
		for i, c := range str {
			if c == ' ' || c == '[' || c == ')' {
				attr = str[:i]
				str = str[i:]
				break
			}
		}
		if len(attr) == 0 {
			attr = str
			str = ""
		}

		// read index
		var index string
		if len(str) > 0 && str[0] == '[' {
			before, after, found := strings.Cut(str[1:], "]")
			if before == "" || !found {
				return nil, str, ErrIndex
			}
			index = before
			str = after
		}

		// read operator
		var op string
		str = strings.TrimSpace(str)
		if len(str) > 1 && str[0:2] != "&&" && str[0:2] != "||" && str[0] != ')' {
			before, after, found := strings.Cut(str, " ")
			if found {
				op = before
				str = after
			}
		}

		// read value
		var val string
		if op != "" {
			str = strings.TrimSpace(str)
			if len(str) == 0 {
				// no value
				return nil, str, ErrValue
			} else if str[0] == '"' {
				// quoted string
				esc := false
				var qs strings.Builder
				for i, c := range str {
					if i == 0 {
						// pass
					} else if esc {
						esc = false
					} else if c == '\\' {
						esc = true
						continue
					} else if c == '"' {
						val = qs.String()
						str = str[i+1:]
						break
					}
					qs.WriteRune(c)
				}
			} else {
				// unquoted string (till space or end of string or closing parenthesis)
				for i, c := range str {
					if c == ' ' || c == ')' {
						val = str[:i]
						str = str[i:]
						break
					}
				}
				if val == "" {
					val = str
					str = ""
				}
			}
		}

		// cut what's left after our expression
		exp.String = strings.TrimSpace(exp.String[:len(exp.String)-len(str)]) // @1

		// basic sanity checks
		if len(attr) == 0 {
			return nil, exp.String, ErrAttr
		} else if op != "" && len(val) == 0 {
			return nil, exp.String, ErrOpValue
		}

		// parse the attribute, index, operator and value
		if !exp.parseAttr(attr) {
			return nil, exp.String, ErrAttr
		} else if !exp.parseIndex(index) {
			return nil, exp.String, ErrIndex
		} else if !exp.parseOp(op) {
			return nil, exp.String, ErrOp
		} else if !exp.parseValue(val) {
			return nil, exp.String, ErrValue
		}

		// more sanity checks for specific attributes
		if err := exp.parseCheck(); err != nil {
			return nil, exp.String, err
		}

		// it's good for use now
		exp.Filter = f
	}

	if lvl > 0 {
		return nil, "", ErrUnmatched // we were expecting a closing parenthesis
	} else {
		return parsed, "", nil
	}
}

func (e *Expr) parseIndex(index string) bool {
	if index == "" {
		return true
	} else if e.Idx != nil {
		return false // already set from elsewhere
	}

	// parse as int?
	if v, err := strconv.Atoi(index); err == nil {
		e.Idx = v
	} else {
		e.Idx = index
	}

	return true
}

func (e *Expr) parseOp(op string) bool {
	if op == "" {
		return true
	} else if e.Op != 0 {
		return false // already set from elsewhere
	}

	switch op {
	case "==", "=":
		e.Op = OP_EQ
	case "!=", "=!":
		e.Op = OP_EQ
		e.OpNot = true
	case "<":
		e.Op = OP_LT
	case "<=":
		e.Op = OP_LE
	case ">":
		e.Op = OP_GT
	case ">=":
		e.Op = OP_GE
	case "~":
		e.Op = OP_LIKE
	case "!~", "~!":
		e.Op = OP_LIKE
		e.OpNot = true
	default:
		return false // invalid operator
	}

	return true
}

func (e *Expr) parseValue(val string) bool {
	if val == "" {
		return true
	} else if e.Val != nil {
		return false // already set from elsewhere
	}

	if val[0] == '"' {
		e.Val = val[1:]
	} else if e.Op == OP_LIKE {
		e.Val = val // attribute handler should interpret this
	} else if v, err := strconv.ParseInt(val, 0, 64); err == nil {
		e.Val = int(v)
	} else if v, err := strconv.ParseFloat(val, 64); err == nil {
		e.Val = v
	} else {
		e.Val = val
	}

	return e.Val != nil
}

// parseAttr parses the attribute name
// it can set the attribute type, operator and value iff needed
func (e *Expr) parseAttr(attr string) bool {
	attr = strings.ToLower(attr)
	attr = strings.ReplaceAll(attr, "-", "_")

	switch attr {
	case "tag", "tags":
		e.Attr = ATTR_TAG

	case "type":
		e.Attr = ATTR_TYPE
	case "update":
		e.Attr = ATTR_TYPE
		e.Op = OP_EQ
		e.Val = msg.UPDATE
	case "open":
		e.Attr = ATTR_TYPE
		e.Op = OP_EQ
		e.Val = msg.OPEN
	case "keepalive":
		e.Attr = ATTR_TYPE
		e.Op = OP_EQ
		e.Val = msg.KEEPALIVE
	case "notify", "notification":
		e.Attr = ATTR_TYPE
		e.Op = OP_EQ
		e.Val = msg.NOTIFY
	case "refresh", "route_refresh":
		e.Attr = ATTR_TYPE
		e.Op = OP_EQ
		e.Val = msg.REFRESH

	case "reach":
		e.Attr = ATTR_REACH
	case "unreach":
		e.Attr = ATTR_UNREACH
	case "prefix":
		e.Attr = ATTR_PREFIX

	case "af":
		e.Attr = ATTR_AF
	case "ipv4":
		e.Attr = ATTR_AF
		e.Op = OP_EQ
		e.Val = afi.AS_IPV4_UNICAST
	case "ipv6":
		e.Attr = ATTR_AF
		e.Op = OP_EQ
		e.Val = afi.AS_IPV6_UNICAST

	case "aspath", "as_path":
		e.Attr = ATTR_ASPATH
	case "as_origin":
		e.Attr = ATTR_ASPATH
		e.Idx = -1
	case "as_upstream":
		e.Attr = ATTR_ASPATH
		e.Idx = -2
	case "as_peer":
		e.Attr = ATTR_ASPATH
		e.Idx = 0
	case "aspath_len", "as_path_len":
		e.Attr = ATTR_ASPATH_LEN
	case "aspath_hops", "as_path_hops":
		e.Attr = ATTR_ASPATH_HOPS

	case "nexthop", "nh":
		e.Attr = ATTR_NEXTHOP

	case "origin":
		e.Attr = ATTR_ORIGIN
	case "med", "metric":
		e.Attr = ATTR_MED
	case "local_pref", "localpref":
		e.Attr = ATTR_LOCALPREF

	case "com", "community":
		e.Attr = ATTR_COMM
	case "com_ext", "ext_community", "ext_com":
		e.Attr = ATTR_COMM_EXT
	case "com_large", "large_community", "large_com":
		e.Attr = ATTR_COMM_LARGE

	case "otc", "only_to_customer":
		e.Attr = ATTR_OTC

	case "dir", "direction":
		e.Attr = ATTR_DIR
	case "seq", "sequence":
		e.Attr = ATTR_SEQ
	case "time", "timestamp":
		e.Attr = ATTR_TIME
	case "json":
		e.Attr = ATTR_JSON
	case "attr":
		e.Attr = ATTR_JSONATTR

	default:
		return false
	}

	return true
}

func (e *Expr) parseCheck() error {
	switch e.Attr {
	case ATTR_EXPR:
		return nil
	case ATTR_TAG:
		return e.tagParse()
	case ATTR_TYPE:
		return e.typeParse()
	case ATTR_AF:
		return e.afParse()
	case ATTR_REACH, ATTR_UNREACH, ATTR_PREFIX:
		return e.prefixParse()
	case ATTR_NEXTHOP:
		return e.nexthopParse()
	case ATTR_ASPATH:
		return e.aspathParse()
	case ATTR_ASPATH_LEN:
		return e.aspathLenParse()
	case ATTR_ASPATH_HOPS:
		return e.aspathLenParse() // same validation as aspath_len
	case ATTR_ORIGIN:
		return e.originParse()
	case ATTR_MED:
		return e.u32Parse()
	case ATTR_LOCALPREF:
		return e.u32Parse()
	case ATTR_COMM, ATTR_COMM_EXT, ATTR_COMM_LARGE:
		return e.communityParse()
	case ATTR_OTC:
		return e.u32Parse()
	case ATTR_DIR:
		return e.dirParse()
	case ATTR_SEQ:
		return e.seqParse()
	case ATTR_TIME:
		return e.timeParse()
	case ATTR_JSON, ATTR_JSONATTR:
		return e.jsonParse()
	default:
		return fmt.Errorf("unsupported attribute")
	}
}

func (e *Expr) eval(ev *Eval) (res bool) {
	res = e.evalAttr(ev)

	// operator negation (!=, !~): negate match only if attribute exists
	if e.OpNot {
		if res {
			res = false // matched → negated to false
		} else {
			res = ev.attrExists(e) // didn't match → true only if attr exists
		}
	}

	if e.Not {
		return !res
	}
	return res
}

func (e *Expr) evalAttr(ev *Eval) bool {
	switch e.Attr {
	case ATTR_EXPR: // sub-expression
		return ev.exprEval(e.Val.(*Expr))
	case ATTR_TAG:
		return e.tagEval(ev)
	case ATTR_TYPE:
		return e.typeEval(ev)
	case ATTR_AF:
		return e.afEval(ev)
	case ATTR_REACH, ATTR_UNREACH, ATTR_PREFIX:
		return e.prefixEval(ev)
	case ATTR_NEXTHOP:
		return e.nexthopEval(ev)
	case ATTR_ASPATH:
		return e.aspathEval(ev)
	case ATTR_ASPATH_LEN:
		return e.aspathLenEval(ev)
	case ATTR_ASPATH_HOPS:
		return e.aspathHopsEval(ev)
	case ATTR_ORIGIN:
		return e.originEval(ev)
	case ATTR_MED:
		return e.medEval(ev)
	case ATTR_LOCALPREF:
		return e.localprefEval(ev)
	case ATTR_COMM, ATTR_COMM_EXT, ATTR_COMM_LARGE:
		return e.communityEval(ev)
	case ATTR_OTC:
		return e.otcEval(ev)
	case ATTR_DIR:
		return e.dirEval(ev)
	case ATTR_SEQ:
		return e.seqEval(ev)
	case ATTR_TIME:
		return e.timeEval(ev)
	case ATTR_JSON, ATTR_JSONATTR:
		return e.jsonEval(ev)
	default:
		panic("not implemented")
	}
}
