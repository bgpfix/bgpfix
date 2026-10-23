package msg

import (
	"testing"

	"github.com/bgpfix/bgpfix/attrs"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/stretchr/testify/require"
)

type panicAttr struct{ attrs.Attr }

func (panicAttr) Unmarshal([]byte, caps.Caps, meta.Meta) error { panic("boom") }

// a parser panic must become an error
func TestParse_Recover(t *testing.T) {
	attrs.NewFuncs[250] = func(cf attrs.CodeFlags) attrs.Attr { return panicAttr{attrs.NewRaw(cf)} }
	defer func() { attrs.NewFuncs[250] = nil }()

	m := NewMsg()
	upd := append(append([]byte{}, BgpMarker...), 0, 27, byte(UPDATE), 0, 0, 0, 4, 0xc0, 250, 1, 0)
	_, err := m.FromBytes(upd)
	require.NoError(t, err)
	require.ErrorIs(t, m.Parse(caps.Caps{}), ErrValue)
	require.Equal(t, INVALID, m.Upper)
}
