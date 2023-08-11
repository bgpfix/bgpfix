package msg

import "strings"

//go:generate go run github.com/dmarkham/enumer -type Afi -trimprefix AFI_
type Afi uint16

const (
	AFI_IPV4            Afi = 1
	AFI_IPV6            Afi = 2
	AFI_L2VPN           Afi = 25
	AFI_MPLS_SECTION    Afi = 26
	AFI_MPLS_LSP        Afi = 27
	AFI_MPLS_PSEUDOWIRE Afi = 28
	AFI_MT_IPV4         Afi = 29
	AFI_MT_IPV6         Afi = 30
	AFI_SFC             Afi = 31
	AFI_LS              Afi = 16388
	AFI_ROUTING_POLICY  Afi = 16398
	AFI_MPLS_NAMESPACES Afi = 16399
)

//go:generate go run github.com/dmarkham/enumer -type Safi -trimprefix SAFI_
type Safi uint8

const (
	SAFI_UNICAST             Safi = 1
	SAFI_MULTICAST           Safi = 2
	SAFI_MPLS                Safi = 4
	SAFI_MCAST_VPN           Safi = 5
	SAFI_PLACEMENT_MSPW      Safi = 6
	SAFI_MCAST_VPLS          Safi = 8
	SAFI_SFC                 Safi = 9
	SAFI_TUNNEL              Safi = 64
	SAFI_VPLS                Safi = 65
	SAFI_MDT                 Safi = 66
	SAFI_4OVER6              Safi = 67
	SAFI_6OVER4              Safi = 68
	SAFI_L1VPN_DISCOVERY     Safi = 69
	SAFI_EVPNS               Safi = 70
	SAFI_LS                  Safi = 71
	SAFI_LS_VPN              Safi = 72
	SAFI_SR_TE_POLICY        Safi = 73
	SAFI_SD_WAN_CAPABILITIES Safi = 74
	SAFI_ROUTING_POLICY      Safi = 75
	SAFI_CLASSFUL_TRANSPORT  Safi = 76
	SAFI_TUNNELED_FLOWSPEC   Safi = 77
	SAFI_MCAST_TREE          Safi = 78
	SAFI_DPS                 Safi = 79
	SAFI_LS_SPF              Safi = 80
	SAFI_CAR                 Safi = 83
	SAFI_VPN_CAR             Safi = 84
	SAFI_MUP                 Safi = 85
	SAFI_MPLS_VPN            Safi = 128
	SAFI_MULTICAST_VPNS      Safi = 129
	SAFI_ROUTE_TARGET        Safi = 132
	SAFI_FLOWSPEC            Safi = 133
	SAFI_L3VPN_FLOWSPEC      Safi = 134
	SAFI_VPN_DISCOVERY       Safi = 140
)

// Asafi represents AFI+SAFI as afi(16) + 0(8) + safi(8)
type Asafi uint32

func AfiSafi(afi Afi, safi Safi) Asafi {
	return Asafi(uint32(afi)<<16 | uint32(safi))
}

func AfiSafiFrom(buf []byte) Asafi {
	if len(buf) == 4 {
		return Asafi(uint32(msb.Uint16(buf[0:2]))<<16 | uint32(buf[3]))
	} else if len(buf) == 3 {
		return Asafi(uint32(msb.Uint16(buf[0:2]))<<16 | uint32(buf[2]))
	} else {
		return 0
	}
}

// Marshal3 marshals AFI + SAFI as 3 bytes
func (as Asafi) Marshal3(dst []byte) []byte {
	dst = msb.AppendUint16(dst, uint16(as.Afi()))
	return append(dst, byte(as.Safi()))
}

func (as Asafi) Afi() Afi {
	return Afi(as >> 16)
}

func (as Asafi) Safi() Safi {
	return Safi(as)
}

func (as Asafi) ToJSON(dst []byte) []byte {
	dst = append(dst, '"')
	dst = append(dst, as.Afi().String()...)
	dst = append(dst, '/')
	dst = append(dst, as.Safi().String()...)
	dst = append(dst, '"')
	return dst
}

func (as Asafi) ToJSONKey(dst []byte, key string) []byte {
	dst = append(dst, '"')
	dst = append(dst, key...)
	dst = append(dst, `":`...)
	return as.ToJSON(dst)
}

func (as *Asafi) FromJSON(src []byte) error {
	s1, s2, ok := strings.Cut(bsu(src), "/")
	if !ok {
		return ErrValue
	}

	afi, err := AfiString(s1)
	if err != nil {
		return err
	}

	safi, err := SafiString(s2)
	if err != nil {
		return err
	}

	*as = AfiSafi(afi, safi)
	return nil
}

// AsafiVal represents AFI+SAFI+VAL as afi(16) + 0(8) + safi(8) + val(32)
type AsafiVal uint64

func AfiSafiVal(afi Afi, safi Safi, val uint32) AsafiVal {
	return AsafiVal(uint64(afi)<<48 | uint64(safi)<<32 | uint64(val))
}

func (asv AsafiVal) Afi() Afi {
	return Afi(asv >> 48)
}

func (asv AsafiVal) Safi() Safi {
	return Safi(asv >> 32)
}

func (asv AsafiVal) Val() uint32 {
	return uint32(asv)
}

// ToJSONAfi interprets Val as an AFI
func (asv AsafiVal) ToJSONAfi(dst []byte) []byte {
	dst = append(dst, '"')
	dst = append(dst, asv.Afi().String()...)
	dst = append(dst, '/')
	dst = append(dst, asv.Safi().String()...)
	dst = append(dst, '/')
	afi := Afi(asv.Val())
	dst = append(dst, afi.String()...)
	dst = append(dst, '"')
	return dst
}
