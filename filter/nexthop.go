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
	if e.Op == OP_PRESENT {
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

func (e *Expr) nexthopEval(ev *Eval) Res {
	nh := ev.Msg.Update.NextHop()
	if !nh.IsValid() {
		return RES_ABSENT
	}
	if e.Op == OP_PRESENT {
		return RES_TRUE
	}
	ref := e.Val.(nlri.Prefix)
	ra := ref.Addr()
	if ra.Is4() != nh.Is4() {
		return RES_FALSE // different address families never match
	}
	switch e.Op {
	case OP_EQ:
		return resBool(ra == nh)
	case OP_LT:
		return resBool(nh.Less(ra))
	case OP_LE:
		return resBool(nh == ra || nh.Less(ra))
	case OP_GT:
		return resBool(ra.Less(nh))
	case OP_GE:
		return resBool(nh == ra || ra.Less(nh))
	case OP_LIKE:
		return resBool(ref.Bits() == 0 || ref.Contains(nh))
	}

	panic("unreachable") // should never happen
}
