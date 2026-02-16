package filter

import "fmt"

// u32Parse validates attributes that are simple uint32 values (med, local_pref)
func (e *Expr) u32Parse() error {
	if e.Idx != nil {
		return ErrIndex
	}

	if e.Op == OP_PRESENT {
		return nil
	}
	if e.Op == OP_LIKE {
		return ErrOp
	}

	v, ok := e.Val.(int)
	if !ok {
		return fmt.Errorf("invalid value: %v (expected integer)", e.Val)
	}
	if v < 0 || int64(v) > 0xFFFFFFFF {
		return fmt.Errorf("value out of range: %d", v)
	}
	e.Val = uint32(v)
	return nil
}

func (e *Expr) medEval(ev *Eval) Res {
	med, ok := ev.Msg.Update.Med()
	if !ok {
		return RES_ABSENT
	}
	return e.u32Eval(med)
}

func (e *Expr) localprefEval(ev *Eval) Res {
	lp, ok := ev.Msg.Update.LocalPref()
	if !ok {
		return RES_ABSENT
	}
	return e.u32Eval(lp)
}

func (e *Expr) otcEval(ev *Eval) Res {
	otc, ok := ev.Msg.Update.Otc()
	if !ok {
		return RES_ABSENT
	}
	return e.u32Eval(otc)
}

func (e *Expr) u32Eval(val uint32) Res {
	if e.Op == OP_PRESENT {
		return RES_TRUE
	}
	ref := e.Val.(uint32)
	switch e.Op {
	case OP_EQ:
		return resBool(val == ref)
	case OP_LT:
		return resBool(val < ref)
	case OP_LE:
		return resBool(val <= ref)
	case OP_GT:
		return resBool(val > ref)
	case OP_GE:
		return resBool(val >= ref)
	}
	return RES_FALSE
}
