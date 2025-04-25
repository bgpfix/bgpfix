package filter

import (
	"bytes"
	"fmt"
	"regexp"
)

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

	// check if index is allowed and is an integer
	if e.Idx != nil {
		if !can_index {
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

		// any index match is ok
		for _, hop := range aspath.Hops() {
			if check_hop(ref, hop) {
				return true
			}
		}
		return false
	}
}
