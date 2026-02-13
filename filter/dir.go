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
	case OP_TRUE:
		// ok
	case OP_EQ:
		s := fmt.Sprintf("%v", e.Val)
		d, err := dir.DirString(s)
		if err != nil {
			return fmt.Errorf("invalid direction: %s (expected L or R)", s)
		}
		e.Val = d
	default:
		return ErrOp
	}

	e.Types = true
	return nil
}

func (e *Expr) dirEval(ev *Eval) bool {
	if e.Op == OP_TRUE {
		return ev.Msg.Dir != 0
	}
	return ev.Msg.Dir == e.Val.(dir.Dir)
}
