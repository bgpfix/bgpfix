package filter

import "fmt"

// u32Parse validates attributes that are simple uint32 values (med, local_pref)
func (e *Expr) u32Parse() error {
	if e.Idx != nil {
		return ErrIndex
	}

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
	if v < 0 || v > 0xFFFFFFFF {
		return fmt.Errorf("value out of range: %d", v)
	}
	e.Val = uint32(v)
	return nil
}

func (e *Expr) medEval(ev *Eval) bool {
	med, ok := ev.Msg.Update.Med()
	if !ok {
		return false
	}
	return e.u32Eval(med)
}

func (e *Expr) localprefEval(ev *Eval) bool {
	lp, ok := ev.Msg.Update.LocalPref()
	if !ok {
		return false
	}
	return e.u32Eval(lp)
}

func (e *Expr) u32Eval(val uint32) bool {
	if e.Op == OP_TRUE {
		return true
	}
	ref := e.Val.(uint32)
	switch e.Op {
	case OP_EQ:
		return val == ref
	case OP_LT:
		return val < ref
	case OP_LE:
		return val <= ref
	case OP_GT:
		return val > ref
	case OP_GE:
		return val >= ref
	}
	return false
}
