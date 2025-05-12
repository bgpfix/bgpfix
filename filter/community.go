package filter

import (
	"fmt"
	"regexp"

	"github.com/bgpfix/bgpfix/attrs"
)

func (e *Expr) communityParse() error {
	// no index allowed
	// IDEA: allow index to match the ASN part of the community (etc)
	if e.Idx != nil {
		return ErrIndex
	}

	// check operator
	switch e.Op {
	case OP_TRUE:
		e.Val = nil
	case OP_EQ:
		// make e.Val a JSON array
		val := fmt.Sprintf("%v", e.Val)
		if val[0] != '[' {
			val = fmt.Sprintf("[ %v ]", e.Val)
		}

		// parse
		switch e.Attr {
		case ATTR_COMM:
			var c attrs.Community
			err := c.FromJSON([]byte(val))
			if err != nil || c.Len() != 1 {
				return ErrValue
			}
			e.Val = c
		case ATTR_COMM_EXT:
			var c attrs.Extcom
			err := c.FromJSON([]byte(val))
			if err != nil || c.Len() != 1 {
				return ErrValue
			}
			e.Val = c
		case ATTR_COMM_LARGE:
			var c attrs.LargeCom
			err := c.FromJSON([]byte(val))
			if err != nil || c.Len() != 1 {
				return ErrValue
			}
			e.Val = c
		}
	case OP_LIKE: // value is a string
		re, err := regexp.Compile(e.Val.(string))
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
		e.Val = re
	default:
		return ErrOp
	}

	return nil
}

func (e *Expr) communityEval(ev *Eval) bool {
	upd := &ev.Msg.Update

	// handle OP_TRUE / OP_EQ, prepare for OP_LIKE otherwise
	var json []byte
	switch e.Attr {
	case ATTR_COMM:
		com := upd.Community()
		if com.Len() == 0 {
			return false
		}
		switch e.Op {
		case OP_TRUE:
			return true
		case OP_EQ:
			ref := e.Val.(attrs.Community)
			asn, val := ref.ASN[0], ref.Value[0]
			for i := range com.ASN {
				if com.ASN[i] == asn && com.Value[i] == val {
					return true // found a match
				}
			}
			return false // no match
		default:
			json = com.ToJSON(json)
		}

	case ATTR_COMM_EXT:
		com := upd.ExtCommunity()
		if com.Len() == 0 {
			return false
		}
		switch e.Op {
		case OP_TRUE:
			return true
		case OP_EQ:
			ref := e.Val.(attrs.Extcom)
			typ, val := ref.Type[0], ref.Value[0].Marshal()
			for i := range com.Type {
				if com.Type[i] == typ && com.Value[i].Marshal() == val {
					return true // found a match
				}
			}
			return false // no match
		default:
			json = com.ToJSON(json)
		}

	case ATTR_COMM_LARGE:
		com := upd.LargeCommunity()
		if com.Len() == 0 {
			return false
		}
		switch e.Op {
		case OP_TRUE:
			return true
		case OP_EQ:
			ref := e.Val.(attrs.LargeCom)
			asn, val1, val2 := ref.ASN[0], ref.Value1[0], ref.Value2[0]
			for i := range com.ASN {
				if com.ASN[i] == asn && com.Value1[i] == val1 && com.Value2[i] == val2 {
					return true // found a match
				}
			}
			return false // no match
		default:
			json = com.ToJSON(json)
		}
	}

	// if we are here, it's an OP_LIKE against JSON of the community values
	if len(json) <= 2 {
		return false // empty json
	} else {
		json = json[1 : len(json)-1] // remove brackets
	}

	// run the regex check
	return e.Val.(*regexp.Regexp).Match(json)
}
