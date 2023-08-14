package af

//go:generate go run github.com/dmarkham/enumer -type SAFI -trimprefix SAFI_
type SAFI uint8

const (
	SAFI_UNICAST             SAFI = 1
	SAFI_MULTICAST           SAFI = 2
	SAFI_MPLS                SAFI = 4
	SAFI_MCAST_VPN           SAFI = 5
	SAFI_PLACEMENT_MSPW      SAFI = 6
	SAFI_MCAST_VPLS          SAFI = 8
	SAFI_SFC                 SAFI = 9
	SAFI_TUNNEL              SAFI = 64
	SAFI_VPLS                SAFI = 65
	SAFI_MDT                 SAFI = 66
	SAFI_4OVER6              SAFI = 67
	SAFI_6OVER4              SAFI = 68
	SAFI_L1VPN_DISCOVERY     SAFI = 69
	SAFI_EVPNS               SAFI = 70
	SAFI_LS                  SAFI = 71
	SAFI_LS_VPN              SAFI = 72
	SAFI_SR_TE_POLICY        SAFI = 73
	SAFI_SD_WAN_CAPABILITIES SAFI = 74
	SAFI_ROUTING_POLICY      SAFI = 75
	SAFI_CLASSFUL_TRANSPORT  SAFI = 76
	SAFI_TUNNELED_FLOWSPEC   SAFI = 77
	SAFI_MCAST_TREE          SAFI = 78
	SAFI_DPS                 SAFI = 79
	SAFI_LS_SPF              SAFI = 80
	SAFI_CAR                 SAFI = 83
	SAFI_VPN_CAR             SAFI = 84
	SAFI_MUP                 SAFI = 85
	SAFI_MPLS_VPN            SAFI = 128
	SAFI_MULTICAST_VPNS      SAFI = 129
	SAFI_ROUTE_TARGET        SAFI = 132
	SAFI_FLOWSPEC            SAFI = 133
	SAFI_L3VPN_FLOWSPEC      SAFI = 134
	SAFI_VPN_DISCOVERY       SAFI = 140
)
