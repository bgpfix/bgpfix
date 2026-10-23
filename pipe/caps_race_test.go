//go:build !race

package pipe

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/meta"
	"github.com/bgpfix/bgpfix/msg"
)

func openAddPath(t *testing.T, asn int) []byte {
	m := msg.NewMsg().Switch(msg.OPEN)
	m.Open.Caps.Init()
	m.Open.SetASN(asn)
	m.Open.HoldTime = 90
	m.Open.Identifier = netip.AddrFrom4([4]byte{10, 0, 0, byte(asn)})
	m.Open.Caps.Use(caps.CAP_ADDPATH).(*caps.AddPath).Add(afi.AS_IPV4_UNICAST, caps.ADDPATH_BIDIR)
	if err := m.Marshal(caps.Caps{}); err != nil {
		t.Fatal(err)
	}
	b := append([]byte{}, msg.BgpMarker...)
	b = append(b, byte(m.Len()>>8), byte(m.Len()), byte(m.Type))
	return append(b, m.Data...)
}

// KEEPALIVE + UPDATE back-to-back must parse the UPDATE with negotiated caps (ADD-PATH)
func TestEstablishedCaps(t *testing.T) {
	ka := append(append([]byte{}, msg.BgpMarker...), 0, 19, 4)
	ats := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xea, 0x40, 3, 4, 10, 0, 0, 1}
	body := append([]byte{0, 0, 0, byte(len(ats))}, ats...)
	body = append(body, 0, 0, 0, 1, 24, 192, 0, 2) // path-id 1, 192.0.2.0/24
	upd := append(append([]byte{}, msg.BgpMarker...), 0, byte(19+len(body)), 2)
	upd = append(upd, body...)

	for i := range 10 {
		p := NewPipe(context.Background())
		p.Options.Logger = nil
		p.Options.StopTimeout = 50 * time.Millisecond
		inR := p.Options.AddInput(meta.DIR_R)
		inL := p.Options.AddInput(meta.DIR_L)
		got := make(chan string, 10)
		p.Options.OnMsg(func(m *msg.Msg) bool {
			got <- m.Update.String()
			return true
		}, meta.DIR_L, msg.UPDATE)
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		go drainLine(p.L)
		go drainLine(p.R)

		inR.Write(openAddPath(t, 1))
		inL.Write(openAddPath(t, 2))
		inR.Write(ka)
		time.Sleep(10 * time.Millisecond)
		inL.Write(append(append([]byte{}, ka...), upd...))

		select {
		case s := <-got:
			if !strings.Contains(s, "#1#192.0.2.0/24") {
				t.Fatalf("run %d: misparsed: %s", i, s)
			}
		case <-time.After(time.Second):
			t.Fatalf("run %d: UPDATE dropped", i)
		}
		p.Stop()
	}
}
