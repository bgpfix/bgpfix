package filter

import (
	"bytes"
	"fmt"
	"regexp"
)

func (e *Expr) aspathLenParse() error {
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
	if !ok || v < 0 {
		return fmt.Errorf("invalid value: %v (expected non-negative integer)", e.Val)
	}
	return nil
}

func (e *Expr) aspathLenEval(ev *Eval) bool {
	aspath := ev.Msg.Update.AsPath()
	if aspath == nil {
		return false
	}
	if e.Op == OP_TRUE {
		return aspath.Len() > 0
	}
	length := aspath.Len()
	ref := e.Val.(int)
	switch e.Op {
	case OP_EQ:
		return length == ref
	case OP_LT:
		return length < ref
	case OP_LE:
		return length <= ref
	case OP_GT:
		return length > ref
	case OP_GE:
		return length >= ref
	}
	return false
}

func (e *Expr) aspathHopsEval(ev *Eval) bool {
	aspath := ev.Msg.Update.AsPath()
	if aspath == nil {
		return false
	}
	if e.Op == OP_TRUE {
		return aspath.UniqueLen() > 0
	}
	length := aspath.UniqueLen()
	ref := e.Val.(int)
	switch e.Op {
	case OP_EQ:
		return length == ref
	case OP_LT:
		return length < ref
	case OP_LE:
		return length <= ref
	case OP_GT:
		return length > ref
	case OP_GE:
		return length >= ref
	}
	return false
}

func (e *Expr) aspathParse() error {
	// verify the operator and value
	ok := false
	can_index := false
	switch e.Op {
	case OP_TRUE:
		ok = true // = non-empty AS_PATH
	case OP_EQ:
		switch v := e.Val.(type) {
		case string:
			if len(v) > 0 {
				ok = true // full path match
				e.Val = []byte(v)
			}
		case int:
			if v >= 0 {
				ok = true // any hop match
				can_index = true
			}
		}
	case OP_LIKE:
		switch v := e.Val.(type) {
		case *regexp.Regexp:
			if v != nil {
				ok = true
			}
		case string:
			re, err := regexp.Compile(v)
			if err != nil {
				return fmt.Errorf("invalid regex: %w", err)
			}
			e.Val = re
			ok = true
		case int:
			e.Op = OP_EQ // any hop match
		}
	default: // <=, >=, <, >
		switch v := e.Val.(type) {
		case int:
			if v >= 0 {
				ok = true
				can_index = true
			}
		}
	}
	if !ok {
		return fmt.Errorf("invalid value: %v", e.Val)
	}

	// check if index is allowed and is an integer (or "*" which means any)
	if e.Idx != nil {
		if e.Idx == "*" {
			e.Idx = nil // [*] = any hop, same as no index
		} else if !can_index {
			return fmt.Errorf("index not allowed: %v", e.Idx)
		} else if _, ok := e.Idx.(int); !ok {
			return fmt.Errorf("invalid index: %v", e.Idx)
		}
	}

	return nil
}

func (e *Expr) aspathEval(ev *Eval) bool {
	// has valid, non-empty AS_PATH?
	aspath := ev.Msg.Update.AsPath()
	if aspath == nil {
		return false
	}

	// to_text converts aspath to JSON without the brackets
	to_text := func() []byte {
		val := aspath.ToJSON(nil)
		return val[1 : len(val)-1]
	}

	// check_hop checks if given hop matches ref
	check_hop := func(ref uint32, hop []uint32) bool {
		for _, asn := range hop {
			switch e.Op {
			case OP_EQ:
				if asn == ref {
					return true
				}
			case OP_LT:
				if asn < ref {
					return true
				}
			case OP_LE:
				if asn <= ref {
					return true
				}
			case OP_GT:
				if asn > ref {
					return true
				}
			case OP_GE:
				if asn >= ref {
					return true
				}
			}
		}
		return false
	}

	switch e.Op {
	case OP_TRUE:
		return true // already checked
	case OP_LIKE:
		re := e.Val.(*regexp.Regexp)
		return re.Match(to_text())
	case OP_EQ:
		if v, ok := e.Val.([]byte); ok {
			return bytes.Equal(v, to_text())
		}
		fallthrough
	default:
		ref := uint32(e.Val.(int))

		// investigate given index only?
		if e.Idx != nil {
			index := e.Idx.(int)
			return check_hop(ref, aspath.Hop(index))
		}

		// any hop match is ok
		for _, hop := range aspath.Hops() {
			if check_hop(ref, hop) {
				return true
			}
		}
		return false
	}
}
