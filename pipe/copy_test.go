package pipe

import (
	"context"
	"testing"

	"github.com/bgpfix/bgpfix/msg"
)

// CopyMsg makes an independent copy with the same contents, metadata and tags
func TestCopyMsg(t *testing.T) {
	p := NewPipe(context.Background())
	m := msg.NewMsg()
	if _, err := m.FromBytes(append(append([]byte{}, msg.BgpMarker...), 0, 19, byte(msg.KEEPALIVE))); err != nil {
		t.Fatal(err)
	}
	m.Seq = 7
	UseContext(m).SetTag("PEER_IP", "192.0.2.1")

	c := p.CopyMsg(m)
	if c == nil || c == m || c.Type != m.Type || c.Seq != 7 || len(c.Data) != len(m.Data) {
		t.Fatalf("bad copy: %v", c)
	}
	if GetTags(c)["PEER_IP"] != "192.0.2.1" {
		t.Errorf("tags not copied: %v", GetTags(c))
	}
	UseContext(m).SetTag("PEER_IP", "x")
	if GetTags(c)["PEER_IP"] != "192.0.2.1" {
		t.Errorf("tags shared")
	}
}
