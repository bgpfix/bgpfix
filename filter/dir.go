package filter

import (
	"fmt"

	"github.com/bgpfix/bgpfix/dir"
)

func (e *Expr) dirParse() error {
	if e.Idx != nil {
		return ErrIndex
	}

	switch e.Op {
	case OP_PRESENT:
		// ok
	case OP_EQ:
		s := fmt.Sprintf("%v", e.Val)
		d, err := dir.DirString(s)
		if err != nil {
			return fmt.Errorf("invalid direction: %s (expected L, R, or LR)", s)
		}
		e.Val = d
	default:
		return ErrOp
	}

	e.Types = true
	return nil
}

func (e *Expr) dirEval(ev *Eval) Res {
	if ev.Msg.Dir == 0 {
		return RES_ABSENT
	}
	if e.Op == OP_PRESENT {
		return RES_TRUE
	}
	return resBool(ev.Msg.Dir == e.Val.(dir.Dir))
}
