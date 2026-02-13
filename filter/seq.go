package filter

import (
	"cmp"
	"fmt"
)

func (e *Expr) seqParse() error {
	if e.Idx != nil {
		return ErrIndex
	}

	e.Types = true

	if e.Op == OP_TRUE {
		return nil
	}
	if e.Op == OP_LIKE {
		return ErrOp
	}

	v, ok := e.Val.(int)
	if !ok {
		return fmt.Errorf("invalid value: %v (expected integer)", e.Val)
	}
	e.Val = int64(v)
	return nil
}

func (e *Expr) seqEval(ev *Eval) bool {
	if e.Op == OP_TRUE {
		return ev.Msg.Seq != 0
	}
	return cmpOp(cmp.Compare(ev.Msg.Seq, e.Val.(int64)), e.Op)
}
