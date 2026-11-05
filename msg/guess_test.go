package msg

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/stretchr/testify/require"
)

// UPDATEs with 2-byte ASNs: AS_PATH 65001 3356 174; AS_PATH 65001 23456 + AGGREGATOR 23456
const (
	as2Path = "ffffffffffffffffffffffffffffffff00300200000016400101004002080203fde90d1c00ae400304c0000201100a01"
	as2Aggr = "ffffffffffffffffffffffffffffffff00400200000026400101004002060202fde95ba0400304c0000201c007065ba00a000001c011060201fa56ea01100a02"
	as2Bad  = "ffffffffffffffffffffffffffffffff00300200000016400101004002080703fde90d1c00ae400304c0000201100a01" // segment type 7
)

func as2Msg(t *testing.T, s string) *Msg {
	raw, err := hex.DecodeString(s)
	require.NoError(t, err)
	m := NewMsg()
	_, err = m.FromBytes(raw)
	require.NoError(t, err)
	return m
}

func TestGuessAS(t *testing.T) {
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)

	// no guessing: fails, nothing recorded
	m := as2Msg(t, as2Path)
	require.Error(t, m.Parse(cps))
	require.Equal(t, int8(0), m.ParseAS4)

	// guessing: 2-byte, recorded in ParseAS4
	cps.Use(caps.CAP_AS_GUESS)
	m = as2Msg(t, as2Path)
	require.NoError(t, m.Parse(cps))
	require.Equal(t, int8(-1), m.ParseAS4)
	require.Equal(t, []uint32{65001, 3356, 174}, m.Update.AsPath().Unique())

	m = as2Msg(t, as2Aggr)
	require.NoError(t, m.Parse(cps))
	require.Equal(t, int8(-1), m.ParseAS4)
	require.Equal(t, uint32(23456), m.Update.Attrs.Get(attrs.ATTR_AGGREGATOR).(*attrs.Aggregator).ASN)

	// not an ASN size problem: fails, nothing recorded
	m = as2Msg(t, as2Bad)
	require.Error(t, m.Parse(cps))
	require.Equal(t, int8(0), m.ParseAS4)

	// explicit meta: no guessing
	m = as2Msg(t, as2Path)
	m.ParseAS4 = 1
	require.Error(t, m.Parse(cps))
	require.Equal(t, int8(1), m.ParseAS4)
}

func TestGuessAS_Remarshal(t *testing.T) {
	var cps caps.Caps
	cps.Use(caps.CAP_AS4)
	cps.Use(caps.CAP_AS_GUESS)

	m := as2Msg(t, as2Path)
	require.NoError(t, m.Parse(cps))
	require.Equal(t, int8(-1), m.ParseAS4)

	// re-encoded data follows cps, and so must ParseAS4
	m.Edit()
	require.NoError(t, m.Marshal(cps))
	require.Equal(t, int8(1), m.ParseAS4)

	// valid 4-byte encoding now
	var bb bytes.Buffer
	_, err := m.WriteTo(&bb)
	require.NoError(t, err)
	m2 := NewMsg()
	_, err = m2.FromBytes(bb.Bytes())
	require.NoError(t, err)
	var cps4 caps.Caps
	cps4.Use(caps.CAP_AS4)
	require.NoError(t, m2.Parse(cps4))
	require.Equal(t, []uint32{65001, 3356, 174}, m2.Update.AsPath().Unique())
}
