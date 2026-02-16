package filter

import (
	"github.com/bgpfix/bgpfix/caps"
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

	cached    int            // msg.Version for which the cache is valid
	cache     map[string]Res // cached results of evaluated expressions
	cacheTime string         // cached formatted timestamp
}

// NewEval creates a new Eval instance.
// The SetMsg method must be called before use.
func NewEval(use_cache bool) *Eval {
	ev := &Eval{}
	if use_cache {
		ev.cache = make(map[string]Res)
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
	ev.cacheTime = ""
}

// getTime returns the formatted timestamp string for the current message.
func (ev *Eval) getTime() string {
	if len(ev.cacheTime) == 0 {
		ev.cacheTime = ev.Msg.Time.Format(msg.JSON_TIME)
	}
	return ev.cacheTime
}

// Run evaluates given Filter f against the current message.
func (ev *Eval) Run(f *Filter) (result bool) {
	if ev.Msg == nil {
		return false
	} else if ev.Msg.Version != ev.cached {
		ev.ClearCache() // the message changed in the meantime
	}

	// check the expressions one by one
	return ev.exprEval(f.First) == RES_TRUE
}

func (ev *Eval) exprEval(first *Expr) Res {
	is_update := ev.Msg.Type == msg.UPDATE
	var prev_and, any_true, any_false bool
	for e := first; e != nil; e = e.Next {
		var res Res
		switch {
		case !is_update && !e.Types:
			res = RES_FALSE // no need to run
		case len(ev.cache) > 0:
			var ok bool
			if res, ok = ev.cache[e.String]; ok {
				break // use cached result in res
			}
			fallthrough
		default:
			res = e.eval(ev)
			if ev.cache != nil {
				ev.cache[e.String] = res
			}
		}

		// any success/ failure so far?
		any_true = any_true || res == RES_TRUE
		any_false = any_false || res == RES_FALSE

		// no need to keep checking?
		is_and := prev_and || e.And // left or right is AND?
		if res == RES_TRUE {
			if !is_and {
				return RES_TRUE // one True in OR chain is enough to succeed
			}
		} else { // = RES_FALSE or RES_ABSENT
			if is_and {
				return RES_FALSE // one False in AND chain is enough to fail
			}
		}
		prev_and = e.And
	}

	if any_true {
		return RES_TRUE // at least one RES_TRUE
	} else if any_false {
		return RES_FALSE // at least one RES_FALSE
	} else {
		return RES_ABSENT // all were RES_ABSENT
	}
}
