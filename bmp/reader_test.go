package bmp

import (
	"context"
	"testing"

	"github.com/bgpfix/bgpfix/pipe"
	"github.com/stretchr/testify/require"
)

// malformed but complete frames must be dropped, not buffered forever
func TestReader_MalformedFrameResyncs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		obmp  bool
		frame []byte
	}{
		{"bmp short peer header", false, []byte{3, 0, 0, 0, 6, byte(MSG_ROUTE_MONITORING)}},
		{"openbmp zero header", true, []byte{'O', 'B', 'M', 'P', 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			br := NewReader(pipe.NewPipe(context.Background()), nil)
			br.OpenBMP = tc.obmp
			_, err := br.Write(tc.frame)
			require.NotNil(t, err)
			require.Zero(t, len(br.ibuf))

			// the junk that follows does not grow the buffer either
			br.Write(make([]byte, 1000))
			require.Less(t, len(br.ibuf), HEADLEN)
		})
	}
}
