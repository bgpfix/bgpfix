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

	// only reach/unreach support OP_TRUE
	if e.Op == OP_TRUE {
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

func (e *Expr) prefixEval(ev *Eval) bool {
	upd := &ev.Msg.Update

	// collect prefixes
	var prefixes []nlri.NLRI
	switch e.Attr {
	case ATTR_REACH:
		prefixes = upd.AllReach()
	case ATTR_UNREACH:
		prefixes = upd.AllUnreach()
	case ATTR_PREFIX:
		prefixes = upd.AllReach() // start with reachable prefixes
	}

	// simple check? (only for reach/unreach)
	if e.Op == OP_TRUE {
		return len(prefixes) > 0
	}

	// check checks specific prefix value
	ref := e.Val.(nlri.NLRI)
	ra, rb := ref.Addr().Unmap(), ref.Bits()
	check := func(pfx *nlri.NLRI) bool {
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
	for i := range 2 {
		for p := range prefixes {
			res := check(&prefixes[p])
			any_ok = any_ok || res
			if all {
				if !res {
					return false // all prefixes must match
				}
			} else {
				if res {
					return true // any match is enough
				}
			}
		}

		// keep searching in unreachable prefixes?
		if i == 0 && e.Attr == ATTR_PREFIX {
			prefixes = upd.AllUnreach()
		} else {
			break
		}
	}

	return any_ok
}
