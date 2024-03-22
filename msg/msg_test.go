package msg

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMsg_Parse(t *testing.T) {
	assert := assert.New(t)

	opMsg := NewMsg()
	opMsg.Type = OPEN

	tests := []struct {
		name    string
		raw     []byte
		wantMsg *Msg
		wantOff int
		wantErr error
	}{
		{
			"too short",
			[]byte{0},
			nil, 0, io.ErrUnexpectedEOF,
		},
		{
			"no marker",
			[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0x00, 0x00, 0x00},
			nil, 0, ErrMarker,
		},
		{
			"invalid length 1",
			append(bgp_marker[:], 0x00, 0x01, 0x00),
			nil, HEADLEN, ErrLength,
		},
		{
			"EOF 65k",
			append(bgp_marker[:], 0xff, 0xff, 0x00),
			nil, HEADLEN, io.ErrUnexpectedEOF,
		},
		{
			"EOF 1",
			append(bgp_marker[:], 0x00, HEADLEN+1, 0x00),
			nil, HEADLEN, io.ErrUnexpectedEOF,
		},
		{
			"OPEN empty",
			append(bgp_marker[:], 0x00, HEADLEN, byte(OPEN), 0x31, 0x37),
			opMsg, HEADLEN, nil,
		},
	}

	msg := NewMsg()
	var buf bytes.Buffer
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			off, err := msg.FromBytes(tt.raw)
			if tt.wantErr == nil {
				assert.NoError(err)
			} else {
				assert.ErrorIs(err, tt.wantErr, "error does not match")
			}

			if tt.wantOff >= 0 {
				assert.Equal(tt.wantOff, off, "offset is wrong")
			}

			if tt.wantMsg != nil {
				assert.Equal(tt.wantMsg, msg, "message is different")
			}

			if err == nil {
				buf.Reset()
				n, err := msg.WriteTo(&buf)
				assert.NoError(err, "write error")
				assert.EqualValues(msg.Length(), n, "wrote different number of bytes")
				assert.Equal(tt.raw[:n], buf.Bytes(), "wrote different message")
			}
		})
	}
}
