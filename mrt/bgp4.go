package mrt

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/bgpfix/bgpfix/pipe"
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

// Bgp4 represents an MRT BGP4MP_MESSAGE message
type Bgp4 struct {
	Mrt       *Mrt       // parent MRT message
	PeerAS    uint32     // peer AS
	LocalAS   uint32     // local AS
	Interface uint16     // interface index
	PeerIP    netip.Addr // peer IP address
	LocalIP   netip.Addr // local IP address
	MsgData   []byte     // raw BGP message, referenced
}

// Init initializes b4 to use parent mrt
func (b4 *Bgp4) Init(mrt *Mrt) {
	b4.Mrt = mrt
}

// Reset prepares b4 for re-use
func (b4 *Bgp4) Reset() {
	b4.MsgData = nil
}

// FromMsg copies BGP message m into BGP4MP message b4.
// m must already be marshaled.
func (b4 *Bgp4) FromMsg(m *msg.Msg) error {
	// m has Data?
	if m.Data == nil {
		return ErrNoData
	}

	// marshal m to b4.Data
	var bb bytes.Buffer
	_, err := m.WriteTo(&bb)
	if err != nil {
		return err
	}
	b4.MsgData = bb.Bytes()

	// update parent Mrt
	mrt := b4.Mrt
	mrt.Time = m.Time
	mrt.Type = BGP4MP_ET
	mrt.Upper = BGP4MP_ET
	mrt.Sub = BGP4_MESSAGE_AS4
	mrt.Data = nil

	// m has Context with tags?
	if tags := pipe.GetContext(m).GetTags(); len(tags) > 0 {
		if s := tags["PEER_AS"]; len(s) > 0 {
			v, err := strconv.ParseUint(s, 10, 32)
			if err == nil {
				b4.PeerAS = uint32(v)
			}
		}
		if s := tags["PEER_IP"]; len(s) > 0 {
			v, err := netip.ParseAddr(s)
			if err == nil {
				b4.PeerIP = v
			}
		}
		if s := tags["LOCAL_AS"]; len(s) > 0 {
			v, err := strconv.ParseUint(s, 10, 32)
			if err == nil {
				b4.LocalAS = uint32(v)
			}
		}
		if s := tags["LOCAL_IP"]; len(s) > 0 {
			v, err := netip.ParseAddr(s)
			if err == nil {
				b4.LocalIP = v
			}
		}
		if s := tags["INTERFACE"]; len(s) > 0 {
			v, err := strconv.ParseUint(s, 10, 16)
			if err == nil {
				b4.Interface = uint16(v)
			}
		}
	}

	return nil
}

// ToMsg reads MRT-BGP4MP message b4 into BGP message m, referencing data.
func (b4 *Bgp4) ToMsg(m *msg.Msg, set_tags bool) error {
	off, err := m.FromBytes(b4.MsgData)
	switch {
	case err != nil:
		return err
	case off != len(b4.MsgData):
		return ErrLength
	}

	// copy MRT time
	m.Time = b4.Mrt.Time

	// copy BGP4MP metadata?
	if set_tags {
		tags := pipe.UseContext(m).UseTags()
		if b4.PeerAS != 0 {
			tags["PEER_AS"] = strconv.FormatUint(uint64(b4.PeerAS), 10)
		}
		if !b4.PeerIP.IsUnspecified() {
			tags["PEER_IP"] = b4.PeerIP.String()
		}
		if b4.LocalAS != 0 {
			tags["LOCAL_AS"] = strconv.FormatUint(uint64(b4.LocalAS), 10)
		}
		if !b4.LocalIP.IsUnspecified() {
			tags["LOCAL_IP"] = b4.LocalIP.String()
		}
		if b4.Interface != 0 {
			tags["INTERFACE"] = strconv.FormatUint(uint64(b4.Interface), 10)
		}
	}

	return nil
}

// Parse parses b4.Mrt as BGP4MP message, referencing data.
func (b4 *Bgp4) Parse() error {
	// check MRT type
	mrt := b4.Mrt
	if !mrt.Type.IsBGP4() {
		return ErrType
	}

	// check buf length
	buf := mrt.Data
	if len(buf) < BGPMSG_HEADLEN {
		return ErrShort
	}

	// read depending on subtype
	var af afi.AFI
	switch mrt.Sub {
	case BGP4_MESSAGE, BGP4_MESSAGE_LOCAL:
		b4.PeerAS = uint32(msb.Uint16(buf[0:2]))
		b4.LocalAS = uint32(msb.Uint16(buf[2:4]))
		b4.Interface = msb.Uint16(buf[4:6])
		af = afi.NewAFIBytes(buf[6:8])
		buf = buf[8:]
	case BGP4_MESSAGE_AS4, BGP4_MESSAGE_AS4_LOCAL:
		b4.PeerAS = msb.Uint32(buf[0:4])
		b4.LocalAS = msb.Uint32(buf[4:8])
		b4.Interface = msb.Uint16(buf[8:10])
		af = afi.NewAFIBytes(buf[10:12])
		buf = buf[12:]
	default:
		return ErrSub
	}

	// parse IP based on AF (NB: the BGPMSG_HEADLEN check above)
	switch af {
	case afi.AFI_IPV4:
		if len(buf) < 2*4+msg.HEADLEN {
			return ErrShort
		}
		b4.PeerIP = netip.AddrFrom4([4]byte(buf[0:4])) // yay go 1.20
		b4.LocalIP = netip.AddrFrom4([4]byte(buf[4:8]))
		buf = buf[2*4:]
	case afi.AFI_IPV6:
		if len(buf) < 2*16+msg.HEADLEN {
			return ErrShort
		}
		b4.PeerIP = netip.AddrFrom16([16]byte(buf[0:16]))
		b4.LocalIP = netip.AddrFrom16([16]byte(buf[16:32]))
		buf = buf[2*16:]
	default:
		return fmt.Errorf("%w: %d", ErrAF, af)
	}

	// reference the raw BGP message
	b4.MsgData = buf

	// done
	mrt.Upper = mrt.Type
	return nil
}

// Marshal marshals b4 to b4.Mrt.Data.
// Type and Sub must already be set in b4.Mrt parent.
func (b4 *Bgp4) Marshal() error {
	// check type
	mrt := b4.Mrt
	switch mrt.Type {
	case BGP4MP:
	case BGP4MP_ET:
	default:
		return ErrType
	}

	// write peer AS, local AS, interface
	buf := mrt.buf[:0]
	switch mrt.Sub {
	case BGP4_MESSAGE, BGP4_MESSAGE_LOCAL:
		buf = msb.AppendUint16(buf, uint16(b4.PeerAS))
		buf = msb.AppendUint16(buf, uint16(b4.LocalAS))
		buf = msb.AppendUint16(buf, b4.Interface)
	case BGP4_MESSAGE_AS4, BGP4_MESSAGE_AS4_LOCAL:
		buf = msb.AppendUint32(buf, b4.PeerAS)
		buf = msb.AppendUint32(buf, b4.LocalAS)
		buf = msb.AppendUint16(buf, b4.Interface)
	default:
		return ErrSub
	}

	// write AF, peer IP, local IP
	peerip := b4.PeerIP.AsSlice()
	localip := b4.PeerIP.AsSlice()
	switch {
	case b4.PeerIP.Is6() || b4.LocalIP.Is6():
		buf = msb.AppendUint16(buf, uint16(afi.AFI_IPV6))
		for len(peerip) < 16 {
			peerip = append(peerip, 0)
		}
		buf = append(buf, peerip[:16]...)
		for len(localip) < 16 {
			localip = append(localip, 0)
		}
		buf = append(buf, localip[:16]...)
	default:
		buf = msb.AppendUint16(buf, uint16(afi.AFI_IPV4))
		for len(peerip) < 4 {
			peerip = append(peerip, 0)
		}
		buf = append(buf, peerip[:4]...)
		for len(localip) < 4 {
			localip = append(localip, 0)
		}
		buf = append(buf, localip[:4]...)
	}

	// write BGP raw data
	buf = append(buf, b4.MsgData...)

	// done
	mrt.Upper = mrt.Type
	mrt.buf = buf
	mrt.Data = buf
	mrt.ref = false
	return nil
}
