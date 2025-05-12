package filter

import (
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/puzpuzpuz/xsync/v3"
)

// Eval efficiently evaluates Filters against a given Msg.
type Eval struct {
	Msg *msg.Msg // message being evaluated

	// optional Pipe context (cleared on Msg change)

	PipeKV   *xsync.MapOf[string, any] // pipe key-value store (can be nil)
	PipeCaps caps.Caps                 // pipe capabilities (can be nil)
	PipeTags map[string]string         // pipe message tags (can be nil)

	cached int             // msg.Version for which the cache is valid
	cache  map[string]bool // cached results of evaluated expressions
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
func (ev *Eval) SetMsg(m *msg.Msg) {
	ev.Msg = m
	ev.ClearCache()
	ev.PipeKV = nil
	ev.PipeCaps.Reset()
	ev.PipeTags = nil
}

// SetPipe sets the optional, read-only Pipe context, in a way that
// hopefully avoids a cyclic import vs. the pipe package.
func (ev *Eval) SetPipe(kv *xsync.MapOf[string, any], caps caps.Caps, tags map[string]string) {
	ev.PipeKV = kv
	ev.PipeCaps = caps
	ev.PipeTags = tags
}

// Clear resets the cache to match the current Msg version.
func (ev *Eval) ClearCache() {
	clear(ev.cache)
	ev.cached = ev.Msg.Version
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
				break // use cached result
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
				return true
			}
		} else {
			if is_and {
				return false
			}
		}
		prev_and = e.And
	}

	return any_ok
}
