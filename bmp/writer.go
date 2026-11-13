package bmp

import (
	"bytes"
	"net/netip"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/msg"
)

// Writer adds what a BMP session needs around Route Monitoring messages:
// the Initiation first, and a Peer Up before the first message of each peer.
// NB: not safe for concurrent use.
type Writer struct {
	SysName  string // sysName in the Initiation
	SysDescr string // sysDescr in the Initiation

	// PeerUp, if set, returns the Peer Up for the peer of b, which was made from m.
	// If it returns nil, or is not set, the Peer Up is synthesized (see NewPeerUp).
	PeerUp func(b *Bmp, m *msg.Msg) *PeerUp

	seen map[peerKey]bool // peers sent so far; nil before the Initiation
	tmp  Bmp
}

// Start appends the Initiation to dst, unless already done.
func (w *Writer) Start(dst []byte) []byte {
	if w.seen != nil {
		return dst
	}
	w.seen = make(map[peerKey]bool)
	w.tmp.Reset().SetInitiation(w.SysName, w.SysDescr)
	w.tmp.Marshal() // NB: can't fail
	return append(dst, w.tmp.Bytes()...)
}

// Prepend appends to dst what must go before Route Monitoring b, made from m
// under caps cps: the Initiation if not sent yet, and the Peer Up of a new peer.
// NB: beyond MAXPEERS peers, no more Peer Ups are sent.
func (w *Writer) Prepend(dst []byte, b *Bmp, m *msg.Msg, cps caps.Caps) []byte {
	dst = w.Start(dst)
	k := peerKey{Type: b.Peer.Type, RD: b.Peer.RD, Address: b.Peer.Address}
	if w.seen[k] || len(w.seen) >= MAXPEERS {
		return dst
	}
	w.seen[k] = true

	var pu *PeerUp
	if w.PeerUp != nil {
		pu = w.PeerUp(b, m)
	}
	if pu == nil {
		pu = NewPeerUp(&b.Peer, m, cps)
	}
	w.tmp.Reset()
	w.tmp.Peer = b.Peer
	w.tmp.SetPeerUp(pu)
	if w.tmp.Marshal() != nil {
		return dst
	}
	return append(dst, w.tmp.Bytes()...)
}

// NewPeerUp returns a Peer Up for peer p with synthesized OPENs: the AS number and
// BGP ID of p, IPv4 and IPv6 unicast plus the families in cps, and ADD-PATH where m has
// Path Identifiers (see msg.Msg.HasAddPath), so a station decodes m right.
func NewPeerUp(p *Peer, m *msg.Msg, cps caps.Caps) *PeerUp {
	mkopen := func(id uint32) []byte {
		om := msg.NewMsg().Switch(msg.OPEN)
		o := &om.Open
		o.Caps.Init()
		o.HoldTime = msg.OPEN_HOLDTIME
		o.Identifier = netip.AddrFrom4([4]byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
		if !p.Is2ByteAS() {
			o.SetASN(p.AS)
		} else if p.AS > 0xffff {
			o.ASN = msg.AS_TRANS
		} else {
			o.ASN = uint16(p.AS)
		}

		mp := o.Caps.Use(caps.CAP_MP).(*caps.MP)
		mp.Add(afi.AFI_IPV4, afi.SAFI_UNICAST)
		mp.Add(afi.AFI_IPV6, afi.SAFI_UNICAST)
		if pmp, ok := cps.Get(caps.CAP_MP).(*caps.MP); ok {
			for _, as := range pmp.Sorted() {
				mp.Add(as.Afi(), as.Safi())
			}
		}
		if ap := m.ParseAddPath; ap != nil {
			for _, as := range ap.AS {
				mp.Add(as.Afi(), as.Safi())
			}
		}
		if m.Upper == msg.UPDATE {
			as := m.Update.AfiSafi()
			mp.Add(as.Afi(), as.Safi())
		}

		// NB: m tells the encoding of one direction only: assume Adj-RIB-In and -Out share it
		for _, as := range mp.Sorted() {
			if m.HasAddPath(as, cps) {
				o.Caps.Use(caps.CAP_ADDPATH).(*caps.AddPath).Add(as, caps.ADDPATH_BIDIR)
			}
		}

		var bb bytes.Buffer
		if om.Marshal(caps.Caps{}) != nil {
			return nil
		} else if _, err := om.WriteTo(&bb); err != nil {
			return nil
		}
		return bb.Bytes()
	}

	local := netip.IPv4Unspecified()
	if p.IsIPv6() {
		local = netip.IPv6Unspecified()
	}
	return &PeerUp{
		LocalAddr:  local,
		LocalPort:  179,
		RemotePort: 179,
		SentOpen:   mkopen(1), // NB: the BGP IDs must differ
		RcvdOpen:   mkopen(p.ID),
	}
}
