package util

import (
	"errors"
	"io"
	"sync"

	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
)

// CopyThrough starts p, runs lhs using R.Input/L.Output and rhs using R.Output/L.Input.
// rhs can be nil, which will close R.Output right away.
// Stops p and closes lhs/rhs before return.
// Returns sent/received bytes in lhsb and rhsb.
func CopyThrough(p *pipe.Pipe, lhs, rhs io.ReadWriteCloser) (lhsb, rhsb []int, err error) {
	var (
		lhs_tx, lhs_rx       int64
		lhs_txerr, lhs_rxerr error
		rhs_tx, rhs_rx       int64
		rhs_txerr, rhs_rxerr error
		wg                   sync.WaitGroup
		rin                  *pipe.Input
		lin                  *pipe.Input
	)

	// add inputs
	po := &p.Options
	rin = po.AddInput(msg.DIR_R)
	if rhs != nil {
		lin = po.AddInput(msg.DIR_L)
	}

	p.Start()

	// LHS: lhs -> R.Input
	wg.Add(1)
	go func() {
		lhs_rx, lhs_rxerr = io.Copy(rin, lhs)
		p.Debug().Err(lhs_rxerr).Msg("CopyThrough: LHS reader done")

		if rhs == nil {
			p.Stop()
		} else {
			rin.Close()
		}

		wg.Done()
	}()

	// LHS: L.Output -> lhs
	wg.Add(1)
	go func() {
		lhs_tx, lhs_txerr = io.Copy(lhs, p.L)
		p.Debug().Err(lhs_txerr).Msg("CopyThrough: LHS writer done")

		lhs.Close()
		wg.Done()
	}()

	// rhs?
	if rhs == nil {
		p.R.CloseOutput()
		// NB: don't close L.Input -> used by LHS callbcks
	} else {
		// RHS: rhs -> L.Input
		wg.Add(1)
		go func() {
			rhs_rx, rhs_rxerr = io.Copy(lin, rhs)
			p.Debug().Err(rhs_rxerr).Msg("CopyThrough: RHS reader done")

			lin.Close()
			wg.Done()
		}()

		// RHS: R.Output -> rhs
		wg.Add(1)
		go func() {
			rhs_tx, rhs_txerr = io.Copy(rhs, p.R)
			p.Debug().Err(rhs_txerr).Msg("CopyThrough: RHS writer done")

			rhs.Close()
			wg.Done()
		}()
	}

	wg.Wait()

	// double-sure
	p.Stop()
	lhs.Close()
	if rhs != nil {
		rhs.Close()
	}

	return []int{int(lhs_tx), int(lhs_rx)},
		[]int{int(rhs_tx), int(rhs_rx)},
		errors.Join(lhs_txerr, lhs_rxerr, rhs_txerr, rhs_rxerr)
}
