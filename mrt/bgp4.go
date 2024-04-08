package mrt

import (
	"fmt"
	"net/netip"

	"github.com/bgpfix/bgpfix/af"
	"github.com/bgpfix/bgpfix/msg"
)

// from https://www.iana.org/assignments/mrt/mrt.xhtml
const (
	BGP4_STATE_CHANGE     Sub = 0
	BGP4_STATE_CHANGE_AS4 Sub = 5

	BGP4_MESSAGE               Sub = 1
	BGP4_MESSAGE_LOCAL         Sub = 6
	BGP4_MESSAGE_ADDPATH       Sub = 8
	BGP4_MESSAGE_LOCAL_ADDPATH Sub = 10

	BGP4_MESSAGE_AS4               Sub = 4
	BGP4_MESSAGE_AS4_LOCAL         Sub = 7
	BGP4_MESSAGE_AS4_ADDPATH       Sub = 9
	BGP4_MESSAGE_AS4_LOCAL_ADDPATH Sub = 11
)

const (
	// minimum MRT BgpMsg header length
	BGPMSG_HEADLEN = 16
)

// Bgp4 represents an MRT BGP4MP message
type Bgp4 struct {
	Mrt     *Mrt       // parent MRT message
	PeerAS  uint32     // peer AS
	LocalAS uint32     // local AS
	Iface   uint16     // interface index
	PeerIP  netip.Addr // peer IP address
	LocalIP netip.Addr // local IP address
	Data    []byte     // BGP message, referenced
}

// Init initializes b4 to use parent mrt
func (b4 *Bgp4) Init(mrt *Mrt) {
	b4.Mrt = mrt
}

// Reset prepares b4 for re-use
func (b4 *Bgp4) Reset() {
	b4.Data = nil
}

// Parse parses bm.Mrt.Data as BGP4MP message
func (b4 *Bgp4) Parse() error {
	// check type
	mrt := b4.Mrt
	switch mrt.Type {
	case BGP4MP:
	case BGP4MP_ET:
	default:
		return ErrType
	}

	// check buf length
	buf := mrt.Data
	if len(buf) < BGPMSG_HEADLEN+msg.HEADLEN {
		return ErrShort
	}

	// read depending on subtype
	var afi af.AFI
	switch mrt.Sub {
	case BGP4_MESSAGE, BGP4_MESSAGE_LOCAL:
		b4.PeerAS = uint32(msb.Uint16(buf[0:2]))
		b4.LocalAS = uint32(msb.Uint16(buf[2:4]))
		b4.Iface = msb.Uint16(buf[4:6])
		afi = af.NewAFIBytes(buf[6:8])
		buf = buf[8:]
	case BGP4_MESSAGE_AS4, BGP4_MESSAGE_AS4_LOCAL:
		b4.PeerAS = msb.Uint32(buf[0:4])
		b4.LocalAS = msb.Uint32(buf[4:8])
		b4.Iface = msb.Uint16(buf[8:10])
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
		b4.PeerIP = netip.AddrFrom4([4]byte(buf[0:4])) // yay go 1.20
		b4.LocalIP = netip.AddrFrom4([4]byte(buf[4:8]))
		buf = buf[2*4:]
	case af.AFI_IPV6:
		if len(buf) < 2*16+msg.HEADLEN {
			return ErrShort
		}
		b4.PeerIP = netip.AddrFrom16([16]byte(buf[0:16]))
		b4.LocalIP = netip.AddrFrom16([16]byte(buf[16:32]))
		buf = buf[2*16:]
	default:
		return fmt.Errorf("%w: %d", ErrAF, afi)
	}

	// reference the message, done
	b4.Data = buf
	return nil
}
