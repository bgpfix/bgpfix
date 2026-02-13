package filter

import (
	"github.com/bgpfix/bgpfix/caps"
	bj "github.com/bgpfix/bgpfix/json"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/puzpuzpuz/xsync/v4"
)

// Eval efficiently evaluates Filters against a given Msg.
type Eval struct {
	Msg *msg.Msg // message being evaluated

	// optional Pipe context (cleared on Msg change)

	PipeKV   *xsync.Map[string, any] // pipe key-value store (can be nil)
	PipeCaps caps.Caps               // pipe capabilities (can be nil)
	PipeTags map[string]string       // pipe message tags (can be nil)

	cached int             // msg.Version for which the cache is valid
	cache  map[string]bool // cached results of evaluated expressions

	// lazy caches for json/time filters
	upperVer int    // msg.Version for which upperJSON is valid
	upperJSON []byte // cached upper layer JSON (element [4] of msg JSON)
	timeVer  int    // msg.Version for which timeFmt is valid
	timeFmt  string // cached formatted timestamp
}

// NewEval creates a new Eval instance.
// The SetMsg method must be called before use.
func NewEval(use_cache bool) *Eval {
	ev := &Eval{}
	if use_cache {
		ev.cache = make(map[string]bool)
	}
	return ev
}

// SetMsg sets the Msg to be evaluated, and clears the Pipe context.
// It must be called before using the Run method.
func (ev *Eval) SetMsg(m *msg.Msg) *Eval {
	ev.Msg = m
	ev.ClearCache()
	ev.PipeKV = nil
	ev.PipeCaps.Reset()
	ev.PipeTags = nil
	return ev
}

// SetPipe sets the optional, read-only Pipe context, in a way that
// avoids a cyclic import vs. the pipe package.
func (ev *Eval) SetPipe(kv *xsync.Map[string, any], caps caps.Caps, tags map[string]string) *Eval {
	ev.PipeKV = kv
	ev.PipeCaps = caps
	ev.PipeTags = tags
	return ev
}

// Set sets the Msg and Pipe context together, for convenience.
func (ev *Eval) Set(m *msg.Msg, kv *xsync.Map[string, any], caps caps.Caps, tags map[string]string) *Eval {
	ev.SetMsg(m)
	ev.SetPipe(kv, caps, tags)
	return ev
}

// ClearCache resets the cache to match the current Msg version.
func (ev *Eval) ClearCache() {
	clear(ev.cache)
	ev.cached = ev.Msg.Version
	ev.upperVer = -1
	ev.timeVer = -1
}

// getUpper returns the upper layer JSON (element [4] of the message JSON array).
// Returns nil for messages with null upper layer (eg. KEEPALIVE).
func (ev *Eval) getUpper() []byte {
	if ev.upperVer != ev.Msg.Version {
		ev.upperVer = ev.Msg.Version
		ev.upperJSON = bj.Get(ev.Msg.GetJSON(), "[4]")
	}
	return ev.upperJSON
}

// getTime returns the formatted timestamp string for the current message.
func (ev *Eval) getTime() string {
	if ev.timeVer != ev.Msg.Version {
		ev.timeVer = ev.Msg.Version
		ev.timeFmt = ev.Msg.Time.Format(msg.JSON_TIME)
	}
	return ev.timeFmt
}

// attrExists checks whether the attribute referenced by e exists in the message.
// Used by OpNot (!=, !~) to distinguish "doesn't exist" from "exists but doesn't match".
func (ev *Eval) attrExists(e *Expr) bool {
	m := ev.Msg
	switch e.Attr {
	case ATTR_EXPR:
		return true
	case ATTR_TAG:
		if e.Idx != nil {
			return ev.PipeTags[e.Idx.(string)] != ""
		}
		return len(ev.PipeTags) > 0
	case ATTR_TYPE:
		return true
	case ATTR_AF:
		return true
	case ATTR_REACH:
		return len(m.Update.AllReach()) > 0
	case ATTR_UNREACH:
		return len(m.Update.AllUnreach()) > 0
	case ATTR_PREFIX:
		return len(m.Update.AllReach()) > 0 || len(m.Update.AllUnreach()) > 0
	case ATTR_ASPATH, ATTR_ASPATH_LEN, ATTR_ASPATH_HOPS:
		return m.Update.AsPath() != nil
	case ATTR_NEXTHOP:
		return m.Update.NextHop().IsValid()
	case ATTR_ORIGIN:
		_, ok := m.Update.Origin()
		return ok
	case ATTR_MED:
		_, ok := m.Update.Med()
		return ok
	case ATTR_LOCALPREF:
		_, ok := m.Update.LocalPref()
		return ok
	case ATTR_COMM:
		return m.Update.Community().Len() > 0
	case ATTR_COMM_EXT:
		return m.Update.ExtCommunity().Len() > 0
	case ATTR_COMM_LARGE:
		return m.Update.LargeCommunity().Len() > 0
	case ATTR_OTC:
		_, ok := m.Update.Otc()
		return ok
	case ATTR_DIR:
		return m.Dir != 0
	case ATTR_SEQ:
		return m.Seq != 0
	case ATTR_TIME:
		return !m.Time.IsZero()
	case ATTR_JSON, ATTR_JSONATTR:
		upper := ev.getUpper()
		if upper == nil {
			return false
		}
		return bj.Get(upper, e.Idx.([]string)...) != nil
	}
	return false
}

// Run evaluates given Filter f against the current message.
func (ev *Eval) Run(f *Filter) (result bool) {
	if ev.Msg == nil {
		return false
	} else if ev.Msg.Version != ev.cached {
		ev.ClearCache() // the message changed in the meantime
	}

	// check the expressions one by one
	return ev.exprEval(f.First)
}

func (ev *Eval) exprEval(first *Expr) (result bool) {
	is_update := ev.Msg.Type == msg.UPDATE
	prev_and := false
	any_ok := false
	for e := first; e != nil; e = e.Next {
		var res, cache_ok bool
		switch {
		case !is_update && !e.Types:
			res = false // no need to run
		case ev.cache != nil:
			if res, cache_ok = ev.cache[e.String]; cache_ok {
				break // use cached result in res
			}
			fallthrough
		default:
			res = e.eval(ev)
			if ev.cache != nil {
				ev.cache[e.String] = res
			}
		}

		// any success so far?
		any_ok = any_ok || res

		// no need to keep checking?
		is_and := prev_and || e.And // left or right is AND?
		if res {
			if !is_and {
				return true // one True in OR chain is enough to succeed
			}
		} else {
			if is_and {
				return false // one False in AND chain is enough to fail
			}
		}
		prev_and = e.And
	}

	return any_ok
}
