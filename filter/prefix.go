package filter

import (
	"fmt"

	"github.com/bgpfix/bgpfix/nlri"
)

func (e *Expr) prefixParse() error {
	// check index
	if e.Idx != nil && e.Idx != "*" {
		return ErrIndex
	}

	// only reach/unreach support OP_PRESENT
	if e.Op == OP_PRESENT {
		if e.Attr == ATTR_PREFIX {
			return ErrOp
		}
		return nil
	}

	// value is string?
	v, ok := e.Val.(string)
	if !ok {
		return fmt.Errorf("invalid value: %v", e.Val)
	}

	// parse
	p, err := nlri.FromString(v)
	if err != nil {
		return fmt.Errorf("invalid value %s: %w", v, err)
	}

	e.Val = p
	return nil
}

func (e *Expr) prefixEval(ev *Eval) Res {
	upd := &ev.Msg.Update

	// collect todo
	var todo [2][]nlri.Prefix
	switch e.Attr {
	case ATTR_REACH:
		todo[0] = upd.AllReach()
	case ATTR_UNREACH:
		todo[0] = upd.AllUnreach()
	case ATTR_PREFIX:
		todo[0] = upd.AllReach()
		todo[1] = upd.AllUnreach()
	}

	// no prefixes at all?
	if len(todo[0])+len(todo[1]) == 0 {
		return RES_ABSENT
	}
	if e.Op == OP_PRESENT {
		return resBool(len(todo[0]) > 0) // only for reach/unreach
	}

	// check checks specific prefix value
	ref := e.Val.(nlri.Prefix)
	ra, rb := ref.Addr().Unmap(), ref.Bits()
	check := func(pfx nlri.Prefix) bool {
		pa, pb := pfx.Addr().Unmap(), pfx.Bits()
		if ra.Is4() != pa.Is4() {
			return false // different address families never match
		}
		switch e.Op {
		case OP_EQ:
			return rb == pb && ra == pa
		case OP_LT:
			return rb < pb && ref.Overlaps(pfx.Prefix)
		case OP_LE:
			return rb <= pb && ref.Overlaps(pfx.Prefix)
		case OP_GT:
			return rb > pb && pfx.Overlaps(ref.Prefix)
		case OP_GE:
			return rb >= pb && ref.Overlaps(pfx.Prefix)
		case OP_LIKE:
			return ref.Overlaps(pfx.Prefix)
		default:
			panic("unreachable")
		}
	}

	// iterate over prefixes, compare vs. ref
	all := e.Idx == "*" // must match all prefixes?
	any_ok := false     // any OK so far?
	for _, prefixes := range todo {
		for _, pfx := range prefixes {
			res := check(pfx)
			any_ok = any_ok || res
			if all {
				if !res {
					return RES_FALSE // all prefixes must match
				}
			} else {
				if res {
					return RES_TRUE // any match is enough
				}
			}
		}
	}

	return resBool(any_ok)
}
