package bmp

import (
	"net/netip"
	"strconv"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/msg"
)

// BMP Information TLV types (RFC 7854 section 4.4)
const (
	INFO_STRING    = 0
	INFO_SYS_DESCR = 1
	INFO_SYS_NAME  = 2
)

// MAXPEERS bounds the per-peer state kept by Reader
const MAXPEERS = 1 << 16

// peerKey identifies a monitored peer (RFC 7854 section 4.2)
type peerKey struct {
	Type    uint8
	RD      uint64
	Address netip.Addr
}

func (p *Peer) key() peerKey {
	return peerKey{p.Type, p.RD, p.Address}
}

// peerState is what Reader knows about a peer
type peerState struct {
	up         bool            // seen Peer Up?
	addpathIn  map[afi.AS]bool // ADD-PATH on routes received from the peer (Adj-RIB-In)
	addpathOut map[afi.AS]bool // ADD-PATH on routes sent to the peer (Adj-RIB-Out)

	as, id             uint32 // peer AS and BGP ID behind the tag values below
	ip, asn, bgpid, rd string // tag values
}

// setTags formats the tag values of p
func (ps *peerState) setTags(p *Peer) {
	ps.as, ps.id = p.AS, p.ID
	ps.ip = p.Address.String()
	ps.asn = strconv.FormatUint(uint64(p.AS), 10)
	ps.bgpid, ps.rd = "", ""
	if p.ID != 0 {
		ps.bgpid = netip.AddrFrom4([4]byte{byte(p.ID >> 24), byte(p.ID >> 16), byte(p.ID >> 8), byte(p.ID)}).String()
	}
	if p.RD != 0 {
		ps.rd = strconv.FormatUint(p.RD, 16)
	}
}

// peer returns the state of p, creating it if needed and create is true.
// Returns nil if not found, or if MAXPEERS is reached.
func (br *Reader) peer(p *Peer, create bool) *peerState {
	if len(br.peers) == 0 && !create {
		return nil
	}
	k := p.key()
	if br.lastps != nil && br.lastkey == k {
		return br.lastps // NB: routers send updates in bursts per peer
	}
	ps := br.peers[k]
	if ps == nil && create && len(br.peers) < MAXPEERS {
		if br.peers == nil {
			br.peers = make(map[peerKey]*peerState)
		}
		ps = new(peerState)
		br.peers[k] = ps
	}
	if ps != nil {
		br.lastkey, br.lastps = k, ps
	}
	return ps
}

// PeerUp represents the body of Peer Up Notification (RFC 7854 section 4.10)
type PeerUp struct {
	LocalAddr  netip.Addr // local address of the monitored router
	LocalPort  uint16     // local TCP port
	RemotePort uint16     // remote TCP port
	SentOpen   []byte     // OPEN sent by the monitored router (full BGP message)
	RcvdOpen   []byte     // OPEN received from the peer (full BGP message)
	Info       []byte     // Information TLVs, if any
}

// bgpLen returns the length of the first BGP message in raw, or 0 if invalid
func bgpLen(raw []byte) int {
	if len(raw) < msg.HEADLEN {
		return 0
	}
	l := int(msb.Uint16(raw[16:18]))
	if l < msg.HEADLEN || l > len(raw) {
		return 0
	}
	return l
}

// PeerUp parses b.Data as Peer Up Notification. References b.Data.
func (b *Bmp) PeerUp(pu *PeerUp) error {
	raw := b.Data
	if b.Type != MSG_PEER_UP || len(raw) < 20 {
		return ErrShort
	}
	if b.Peer.IsIPv6() {
		pu.LocalAddr = netip.AddrFrom16([16]byte(raw[0:16]))
	} else {
		pu.LocalAddr = netip.AddrFrom4([4]byte(raw[12:16]))
	}
	pu.LocalPort = msb.Uint16(raw[16:18])
	pu.RemotePort = msb.Uint16(raw[18:20])
	raw = raw[20:]

	l := bgpLen(raw)
	if l == 0 {
		return ErrLength
	}
	pu.SentOpen, raw = raw[:l], raw[l:]
	if l = bgpLen(raw); l == 0 {
		return ErrLength
	}
	pu.RcvdOpen, pu.Info = raw[:l], raw[l:]
	return nil
}

// SetPeerUp makes b a Peer Up Notification for b.Peer, to be marshaled next.
func (b *Bmp) SetPeerUp(pu *PeerUp) {
	b.Type = MSG_PEER_UP
	buf := make([]byte, 20, 20+len(pu.SentOpen)+len(pu.RcvdOpen)+len(pu.Info))
	if pu.LocalAddr.Is4() {
		copy(buf[12:16], pu.LocalAddr.AsSlice())
	} else if pu.LocalAddr.IsValid() {
		copy(buf[0:16], pu.LocalAddr.AsSlice())
	}
	msb.PutUint16(buf[16:18], pu.LocalPort)
	msb.PutUint16(buf[18:20], pu.RemotePort)
	buf = append(buf, pu.SentOpen...)
	buf = append(buf, pu.RcvdOpen...)
	b.Data = append(buf, pu.Info...)
}

// SetPeerDown makes b a Peer Down Notification for b.Peer (reason 5: de-configured),
// or reason 1 (local NOTIFICATION) if notify is a BGP message.
func (b *Bmp) SetPeerDown(notify []byte) {
	b.Type = MSG_PEER_DOWN
	if len(notify) > 0 {
		b.Data = append([]byte{1}, notify...)
	} else {
		b.Data = []byte{5}
	}
}

// AppendInfo appends an Information TLV to dst
func AppendInfo(dst []byte, typ uint16, val string) []byte {
	dst = msb.AppendUint16(dst, typ)
	dst = msb.AppendUint16(dst, uint16(len(val)))
	return append(dst, val...)
}

// SetInitiation makes b an Initiation message, to be marshaled next.
func (b *Bmp) SetInitiation(sysName, sysDescr string) {
	b.Type = MSG_INITIATION
	b.Data = AppendInfo(AppendInfo(nil, INFO_SYS_DESCR, sysDescr), INFO_SYS_NAME, sysName)
}

// SetTermination makes b a Termination message with given reason code.
func (b *Bmp) SetTermination(reason uint16) {
	b.Type = MSG_TERMINATION
	b.Data = msb.AppendUint16([]byte{0, 1, 0, 2}, reason)
}

// addpath returns the address families with ADD-PATH negotiated from snd to rcv, or nil if none
func addpath(snd, rcv *msg.Msg) (on map[afi.AS]bool) {
	s, _ := snd.Open.Caps.Get(caps.CAP_ADDPATH).(*caps.AddPath)
	r, _ := rcv.Open.Caps.Get(caps.CAP_ADDPATH).(*caps.AddPath)
	if s == nil || r == nil {
		return nil
	}
	for as := range s.Proto {
		if s.Has(as, caps.ADDPATH_SEND) && r.Has(as, caps.ADDPATH_RECEIVE) {
			if on == nil {
				on = make(map[afi.AS]bool)
			}
			on[as] = true
		}
	}
	return on
}

// track updates the reader state with a non-Route-Monitoring message bm.
// Returns BGP messages to emit, if any (only in br.Session mode).
func (br *Reader) track(bm *Bmp) (bgps [][]byte) {
	switch bm.Type {
	case MSG_INITIATION:
		for raw := bm.Data; len(raw) >= 4; {
			typ, l := msb.Uint16(raw[0:2]), int(msb.Uint16(raw[2:4]))
			if l > len(raw)-4 {
				break
			} else if typ == INFO_SYS_NAME {
				br.Router = string(raw[4 : 4+l])
			}
			raw = raw[4+l:]
		}

	case MSG_PEER_UP:
		br.Stats.PeerUp++
		var pu PeerUp
		if bm.PeerUp(&pu) != nil {
			return nil
		}

		// parse both OPENs for the negotiated ADD-PATH
		sent, rcvd := msg.NewMsg(), msg.NewMsg()
		if _, err := sent.FromBytes(pu.SentOpen); err != nil || sent.Parse(caps.Caps{}) != nil || sent.Type != msg.OPEN || sent.Open.ParseCaps() != nil {
			return nil
		}
		if _, err := rcvd.FromBytes(pu.RcvdOpen); err != nil || rcvd.Parse(caps.Caps{}) != nil || rcvd.Type != msg.OPEN || rcvd.Open.ParseCaps() != nil {
			return nil
		}
		if ps := br.peer(&bm.Peer, true); ps != nil {
			ps.up = true
			ps.addpathIn = addpath(rcvd, sent)
			ps.addpathOut = addpath(sent, rcvd)
		}
		if br.Session {
			bgps = append(bgps, pu.SentOpen, pu.RcvdOpen)
		}

	case MSG_PEER_DOWN:
		br.Stats.PeerDown++
		delete(br.peers, bm.Peer.key())
		br.lastps = nil

		// reasons 1 and 3 carry a NOTIFICATION
		if br.Session && len(bm.Data) > 1 && (bm.Data[0] == 1 || bm.Data[0] == 3) {
			if l := bgpLen(bm.Data[1:]); l > 0 {
				bgps = append(bgps, bm.Data[1:1+l])
			}
		}

	case MSG_ROUTE_MIRRORING:
		// TLV type 0 is a verbatim BGP message
		for raw := bm.Data; br.Session && len(raw) >= 4; {
			typ, l := msb.Uint16(raw[0:2]), int(msb.Uint16(raw[2:4]))
			if l > len(raw)-4 {
				break
			} else if typ == 0 && bgpLen(raw[4:4+l]) == l {
				bgps = append(bgps, raw[4:4+l])
			}
			raw = raw[4+l:]
		}
	}
	return bgps
}
