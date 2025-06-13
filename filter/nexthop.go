package filter

import (
	"fmt"

	"github.com/bgpfix/bgpfix/nlri"
)

func (e *Expr) nexthopParse() error {
	// check index
	if e.Idx != nil {
		return ErrIndex
	}

	// OP_TRUE is simple
	if e.Op == OP_TRUE {
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

	// makes sense?
	if !p.IsSingleIP() && e.Op != OP_LIKE {
		return fmt.Errorf("value must be a single IP address for this operator")
	}

	e.Val = p
	return nil
}

func (e *Expr) nexthopEval(ev *Eval) bool {
	upd := &ev.Msg.Update

	// get message nexthop
	nh := upd.NextHop()
	if !nh.IsValid() {
		return false // no nexthop, or invalid value
	} else if e.Op == OP_TRUE {
		return true // any nexthop is OK
	}

	// check
	ref := e.Val.(nlri.NLRI)
	ra := ref.Addr()
	if ra.Is4() != nh.Is4() {
		return false // different address families never match
	}
	switch e.Op {
	case OP_EQ:
		return ra == nh
	case OP_LT:
		return nh.Less(ra)
	case OP_LE:
		return nh == ra || nh.Less(ra)
	case OP_GT:
		return ra.Less(nh)
	case OP_GE:
		return nh == ra || ra.Less(nh)
	case OP_LIKE:
		return ref.Bits() == 0 || ref.Contains(nh)
	}

	panic("unreachable") // should never happen
}
