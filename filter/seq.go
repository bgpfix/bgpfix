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

	switch e.Op {
	case OP_PRESENT:
		return nil // ok
	case OP_EQ, OP_LT, OP_LE, OP_GT, OP_GE:
		break // value must be an integer
	default:
		return ErrOp
	}

	v, ok := e.Val.(int)
	if !ok {
		return fmt.Errorf("invalid value: %v (expected integer)", e.Val)
	}
	e.Val = int64(v)

	return nil
}

func (e *Expr) seqEval(ev *Eval) Res {
	if ev.Msg.Seq == 0 {
		return RES_ABSENT
	} else if e.Op == OP_PRESENT {
		return RES_TRUE
	}

	return resCmp(e.Op, cmp.Compare(ev.Msg.Seq, e.Val.(int64)))
}
