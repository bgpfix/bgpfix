package msg

import (
	"testing"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/stretchr/testify/require"
)

func TestNotify_JSON(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		json string
	}{
		{"no data", []byte{2, 2}, `{"code":2,"subcode":2,"name":"OPEN Message Error/Bad Peer AS","data":""}`},
		{"shutdown", append([]byte{6, 2, 3}, "bye"...), `{"code":6,"subcode":2,"name":"Cease/Administrative Shutdown","data":"0x03627965","text":"bye"}`},
		{"utf-8 shutdown", append([]byte{6, 4, 4}, "\u017c\u00f3"...), `{"code":6,"subcode":4,"name":"Cease/Administrative Reset","data":"0x04c5bcc3b3","text":"` + "\u017c\u00f3" + `"}`},
		{"unknown", []byte{99, 7, '"', 0xff}, `{"code":99,"subcode":7,"name":"99/7","data":"0x22ff"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMsg()
			m.Type = NOTIFY
			m.Data = tc.data
			require.NoError(t, m.Parse(caps.Caps{}))
			require.Contains(t, string(m.GetJSON()), `"NOTIFY",`+tc.json)

			// roundtrip
			m2 := NewMsg()
			require.NoError(t, m2.FromJSON(m.GetJSON()))
			require.Equal(t, NOTIFY, m2.Upper)
			require.Equal(t, tc.data, m2.Data)
		})
	}
}
