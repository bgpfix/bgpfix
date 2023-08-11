package mrt

import (
	"fmt"
	"net/netip"

	bgp "github.com/bgpfix/bgpfix/msg"
)

// from https://www.iana.org/assignments/mrt/mrt.xhtml
const (
	BGP4MP_STATE_CHANGE     MsgSub = 0
	BGP4MP_STATE_CHANGE_AS4 MsgSub = 5

	BGP4MP_MESSAGE               MsgSub = 1
	BGP4MP_MESSAGE_LOCAL         MsgSub = 6
	BGP4MP_MESSAGE_ADDPATH       MsgSub = 8
	BGP4MP_MESSAGE_LOCAL_ADDPATH MsgSub = 10

	BGP4MP_MESSAGE_AS4               MsgSub = 4
	BGP4MP_MESSAGE_AS4_LOCAL         MsgSub = 7
	BGP4MP_MESSAGE_AS4_ADDPATH       MsgSub = 9
	BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH MsgSub = 11
)

const (
	// minimum MRT BgpMsg header length
	BGPMSG_HEADLEN = 16
)

// BgpMsg represents MRT BGP4MP message
type BgpMsg struct {
	msg     *Msg
	PeerAS  uint32     // peer AS
	LocalAS uint32     // local AS
	Iface   uint16     // interface index
	PeerIP  netip.Addr // peer IP address
	LocalIP netip.Addr // local IP address
	Data    []byte     // BGP message, referenced from msg
}

// Reset resets b to initial state, dropping all references
func (b *BgpMsg) Reset() {
	*b = BgpMsg{}
}

// Parse parses BGP4MP message from MRT message m.
func (b *BgpMsg) Parse(m *Msg) error {
	b.msg = m

	// check type
	switch m.Type {
	case TYPE_BGP4MP:
	case TYPE_BGP4MP_ET:
	default:
		return ErrType
	}

	// check buf length
	buf := m.Data
	if len(buf) < BGPMSG_HEADLEN+bgp.MSG_HEADLEN {
		return ErrShort
	}

	// read depending on subtype
	var af uint16
	switch m.Sub {
	case BGP4MP_MESSAGE, BGP4MP_MESSAGE_LOCAL:
		b.PeerAS = uint32(msb.Uint16(buf[0:2]))
		b.LocalAS = uint32(msb.Uint16(buf[2:4]))
		b.Iface = msb.Uint16(buf[4:6])
		af = msb.Uint16(buf[6:8])
		buf = buf[8:]
	case BGP4MP_MESSAGE_AS4, BGP4MP_MESSAGE_AS4_LOCAL:
		b.PeerAS = msb.Uint32(buf[0:4])
		b.LocalAS = msb.Uint32(buf[4:8])
		b.Iface = msb.Uint16(buf[8:10])
		af = msb.Uint16(buf[10:12])
		buf = buf[12:]
	default:
		return ErrSub
	}

	// parse IP based on AF (NB: the BGPMSG_MINLEN check above)
	switch af {
	case AFI_IPv4:
		if len(buf) < 2*4+bgp.MSG_HEADLEN {
			return ErrShort
		}
		b.PeerIP = netip.AddrFrom4([4]byte(buf[0:4])) // yay go 1.20
		b.LocalIP = netip.AddrFrom4([4]byte(buf[4:8]))
		buf = buf[2*4:]
	case AFI_IPv6:
		if len(buf) < 2*16+bgp.MSG_HEADLEN {
			return ErrShort
		}
		b.PeerIP = netip.AddrFrom16([16]byte(buf[0:16]))
		b.LocalIP = netip.AddrFrom16([16]byte(buf[16:32]))
		buf = buf[2*16:]
	default:
		return fmt.Errorf("%w: %d", ErrAF, af)
	}

	// reference the message, done
	b.Data = buf
	return nil
}
