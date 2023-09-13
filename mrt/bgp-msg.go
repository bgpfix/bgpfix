package mrt

import (
	"fmt"
	"net/netip"

	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/msg"
)

// from https://www.iana.org/assignments/mrt/mrt.xhtml
const (
	BGP4MP_STATE_CHANGE     Sub = 0
	BGP4MP_STATE_CHANGE_AS4 Sub = 5

	BGP4MP_MESSAGE               Sub = 1
	BGP4MP_MESSAGE_LOCAL         Sub = 6
	BGP4MP_MESSAGE_ADDPATH       Sub = 8
	BGP4MP_MESSAGE_LOCAL_ADDPATH Sub = 10

	BGP4MP_MESSAGE_AS4               Sub = 4
	BGP4MP_MESSAGE_AS4_LOCAL         Sub = 7
	BGP4MP_MESSAGE_AS4_ADDPATH       Sub = 9
	BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH Sub = 11
)

const (
	// minimum MRT BgpMsg header length
	BGPMSG_HEADLEN = 16
)

// BgpMsg represents an MRT BGP4MP message
type BgpMsg struct {
	Mrt     *Mrt       // parent MRT message
	PeerAS  uint32     // peer AS
	LocalAS uint32     // local AS
	Iface   uint16     // interface index
	PeerIP  netip.Addr // peer IP address
	LocalIP netip.Addr // local IP address
	Data    []byte     // BGP message, referenced from Mrt
}

// Reset resets b to initial state, dropping all references
func (b *BgpMsg) Reset() *BgpMsg {
	*b = BgpMsg{}
	return b
}

// Parse parses BGP4MP message from MRT message m.
func (bm *BgpMsg) Parse(m *Mrt) error {
	bm.Mrt = m

	// check type
	switch m.Type {
	case TYPE_BGP4MP:
	case TYPE_BGP4MP_ET:
	default:
		return ErrType
	}

	// check buf length
	buf := m.Data
	if len(buf) < BGPMSG_HEADLEN+msg.HEADLEN {
		return ErrShort
	}

	// read depending on subtype
	var afi af.AFI
	switch m.Sub {
	case BGP4MP_MESSAGE, BGP4MP_MESSAGE_LOCAL:
		bm.PeerAS = uint32(msb.Uint16(buf[0:2]))
		bm.LocalAS = uint32(msb.Uint16(buf[2:4]))
		bm.Iface = msb.Uint16(buf[4:6])
		afi = af.NewAFIBytes(buf[6:8])
		buf = buf[8:]
	case BGP4MP_MESSAGE_AS4, BGP4MP_MESSAGE_AS4_LOCAL:
		bm.PeerAS = msb.Uint32(buf[0:4])
		bm.LocalAS = msb.Uint32(buf[4:8])
		bm.Iface = msb.Uint16(buf[8:10])
		afi = af.NewAFIBytes(buf[10:12])
		buf = buf[12:]
	default:
		return ErrSub
	}

	// parse IP based on AF (NB: the BGPMSG_MINLEN check above)
	switch afi {
	case af.AFI_IPV4:
		if len(buf) < 2*4+msg.HEADLEN {
			return ErrShort
		}
		bm.PeerIP = netip.AddrFrom4([4]byte(buf[0:4])) // yay go 1.20
		bm.LocalIP = netip.AddrFrom4([4]byte(buf[4:8]))
		buf = buf[2*4:]
	case af.AFI_IPV6:
		if len(buf) < 2*16+msg.HEADLEN {
			return ErrShort
		}
		bm.PeerIP = netip.AddrFrom16([16]byte(buf[0:16]))
		bm.LocalIP = netip.AddrFrom16([16]byte(buf[16:32]))
		buf = buf[2*16:]
	default:
		return fmt.Errorf("%w: %d", ErrAF, afi)
	}

	// reference the message, done
	bm.Data = buf
	return nil
}
