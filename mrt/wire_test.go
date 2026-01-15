package mrt

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/msg"
	"github.com/stretchr/testify/require"
)

func appendUint16(dst []byte, v uint16) []byte {
	return append(dst, byte(v>>8), byte(v))
}

func appendUint32(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func makeBgpHeader(totalLen uint16, typ msg.Type) []byte {
	buf := make([]byte, msg.HEADLEN)
	copy(buf, msg.BgpMarker)
	buf[16] = byte(totalLen >> 8)
	buf[17] = byte(totalLen)
	buf[18] = byte(typ)
	return buf
}

func makeBgpKeepalive() []byte {
	return makeBgpHeader(msg.HEADLEN, msg.KEEPALIVE)
}

func makeMrtHeader(ts uint32, typ Type, sub Sub, length uint32) []byte {
	buf := make([]byte, 0, HEADLEN)
	buf = appendUint32(buf, ts)
	buf = appendUint16(buf, uint16(typ))
	buf = appendUint16(buf, uint16(sub))
	buf = appendUint32(buf, length)
	return buf
}

func makeBGP4MPAS4(peerAS, localAS uint32, iface uint16, af afi.AFI, peerIP, localIP netip.Addr, bgp []byte) []byte {
	buf := make([]byte, 0, 32+len(bgp))
	buf = appendUint32(buf, peerAS)
	buf = appendUint32(buf, localAS)
	buf = appendUint16(buf, iface)
	buf = appendUint16(buf, uint16(af))
	buf = append(buf, peerIP.AsSlice()...)
	buf = append(buf, localIP.AsSlice()...)
	return append(buf, bgp...)
}

func TestMRT_FromBytes_ValidETBGP4(t *testing.T) {
	bgp := makeBgpKeepalive()
	peerIP := netip.AddrFrom4([4]byte{192, 0, 2, 1})
	localIP := netip.AddrFrom4([4]byte{192, 0, 2, 1})
	b4 := makeBGP4MPAS4(65001, 65002, 1, afi.AFI_IPV4, peerIP, localIP, bgp)

	extTS := uint32(500000)
	data := append(appendUint32(nil, extTS), b4...)
	raw := append(makeMrtHeader(1700000000, BGP4MP_ET, BGP4_MESSAGE_AS4, uint32(len(data))), data...)

	m := NewMrt()
	off, err := m.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, BGP4MP_ET, m.Type)
	require.Equal(t, BGP4_MESSAGE_AS4, m.Sub)
	require.Equal(t, len(b4), len(m.Data))

	expectedTime := time.Unix(1700000000, 0).UTC().Add(500000 * time.Microsecond)
	require.True(t, m.Time.Equal(expectedTime))

	err = m.Parse()
	require.NoError(t, err)
	require.Equal(t, uint32(65001), m.Bgp4.PeerAS)
	require.Equal(t, uint32(65002), m.Bgp4.LocalAS)
	require.Equal(t, uint16(1), m.Bgp4.Interface)
	require.Equal(t, peerIP, m.Bgp4.PeerIP)
	require.Equal(t, localIP, m.Bgp4.LocalIP)
	require.Equal(t, bgp, m.Bgp4.MsgData)
}

func TestMRT_FromBytes_Truncated(t *testing.T) {
	short := []byte{0x00}
	msg := NewMrt()
	_, err := msg.FromBytes(short)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)

	head := makeMrtHeader(0, BGP4MP, BGP4_MESSAGE, 10)
	buf := append(head, 0x01, 0x02)
	_, err = msg.FromBytes(buf)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestBGP4_Parse_InvalidAF(t *testing.T) {
	m := NewMrt()
	m.Type = BGP4MP
	m.Sub = BGP4_MESSAGE_AS4
	m.Data = []byte{
		0x00, 0x00, 0xFD, 0xE9,
		0x00, 0x00, 0xFD, 0xEA,
		0x00, 0x01,
		0x12, 0x34,
		0x00, 0x00, 0x00, 0x00,
	}

	err := m.Bgp4.Parse()
	require.ErrorIs(t, err, ErrAF)
}

func TestBGP4_Marshal_Parse_RoundTrip(t *testing.T) {
	bgp := makeBgpKeepalive()
	peerIP := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	localIP := netip.AddrFrom4([4]byte{10, 0, 0, 2})

	m := NewMrt()
	m.Type = BGP4MP
	m.Sub = BGP4_MESSAGE_AS4

	b4 := &m.Bgp4
	b4.PeerAS = 4200000001
	b4.LocalAS = 4200000002
	b4.Interface = 2
	b4.PeerIP = peerIP
	b4.LocalIP = localIP
	b4.MsgData = bgp

	err := b4.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, m.Data)

	m2 := NewMrt()
	m2.Type = m.Type
	m2.Sub = m.Sub
	m2.Data = m.Data

	err = m2.Bgp4.Parse()
	require.NoError(t, err)
	require.Equal(t, b4.PeerAS, m2.Bgp4.PeerAS)
	require.Equal(t, b4.LocalAS, m2.Bgp4.LocalAS)
	require.Equal(t, b4.Interface, m2.Bgp4.Interface)
	require.Equal(t, peerIP, m2.Bgp4.PeerIP)
	require.Equal(t, localIP, m2.Bgp4.LocalIP)
	require.Equal(t, bgp, m2.Bgp4.MsgData)
}

func TestBGP4_IPv6_RoundTrip(t *testing.T) {
	bgp := makeBgpKeepalive()
	peerIP := netip.MustParseAddr("2001:db8::1")
	localIP := netip.MustParseAddr("2001:db8::2")

	m := NewMrt()
	m.Type = BGP4MP
	m.Sub = BGP4_MESSAGE_AS4

	b4 := &m.Bgp4
	b4.PeerAS = 65001
	b4.LocalAS = 65002
	b4.Interface = 1
	b4.PeerIP = peerIP
	b4.LocalIP = localIP
	b4.MsgData = bgp

	err := b4.Marshal()
	require.NoError(t, err)

	m2 := NewMrt()
	m2.Type = m.Type
	m2.Sub = m.Sub
	m2.Data = m.Data

	err = m2.Bgp4.Parse()
	require.NoError(t, err)
	require.Equal(t, peerIP, m2.Bgp4.PeerIP)
	require.Equal(t, localIP, m2.Bgp4.LocalIP)
}

func TestMRT_NonET_Parse(t *testing.T) {
	bgp := makeBgpKeepalive()
	peerIP := netip.AddrFrom4([4]byte{192, 0, 2, 1})
	localIP := netip.AddrFrom4([4]byte{192, 0, 2, 2})
	b4 := makeBGP4MPAS4(65001, 65002, 0, afi.AFI_IPV4, peerIP, localIP, bgp)

	raw := append(makeMrtHeader(1700000000, BGP4MP, BGP4_MESSAGE_AS4, uint32(len(b4))), b4...)

	m := NewMrt()
	off, err := m.FromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, len(raw), off)
	require.Equal(t, BGP4MP, m.Type)
	require.False(t, m.Type.IsET())

	err = m.Parse()
	require.NoError(t, err)
	require.Equal(t, uint32(65001), m.Bgp4.PeerAS)
}
