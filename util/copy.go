package util

import (
	"errors"
	"io"
	"sync"

	"github.com/bgpfix/bgpfix/pipe"
)

// CopyThrough starts p, runs lhs using Rx.Input/Tx.Output and rhs using Rx.Output/Tx.Input.
// rhs can be nil, which will close Rx.Output right away.
// Stops p and closes lhs/rhs before return.
// Returns sent/received bytes in lhsb and rhsb.
func CopyThrough(p *pipe.Pipe, lhs, rhs io.ReadWriteCloser) (lhsb, rhsb []int, err error) {
	var (
		lhs_tx, lhs_rx       int64
		lhs_txerr, lhs_rxerr error
		rhs_tx, rhs_rx       int64
		rhs_txerr, rhs_rxerr error
		wg                   sync.WaitGroup
	)

	p.Start()

	// LHS: lhs -> RX.Input
	wg.Add(1)
	go func() {
		lhs_rx, lhs_rxerr = io.Copy(p.Rx, lhs)
		p.Debug().Err(lhs_rxerr).Msg("CopyThrough: LHS reader done")

		if rhs == nil {
			p.Stop()
		} else {
			p.Rx.CloseInput()
		}

		wg.Done()
	}()

	// LHS: TX.Output -> lhs
	wg.Add(1)
	go func() {
		lhs_tx, lhs_txerr = io.Copy(lhs, p.Tx)
		p.Debug().Err(lhs_txerr).Msg("CopyThrough: LHS writer done")

		lhs.Close()
		wg.Done()
	}()

	// rhs?
	if rhs == nil {
		p.Rx.CloseOutput()
		// NB: don't close TX.Input -> used by LHS callbcks
	} else {
		// RHS: rhs -> TX.Input
		wg.Add(1)
		go func() {
			rhs_rx, rhs_rxerr = io.Copy(p.Tx, rhs)
			p.Debug().Err(rhs_rxerr).Msg("CopyThrough: RHS reader done")

			p.Tx.CloseInput()
			wg.Done()
		}()

		// RHS: RX.Output -> rhs
		wg.Add(1)
		go func() {
			rhs_tx, rhs_txerr = io.Copy(rhs, p.Rx)
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
