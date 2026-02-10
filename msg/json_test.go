package msg

import (
	"net/netip"
	"testing"
	"time"

	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/dir"
	"github.com/bgpfix/bgpfix/nlri"
	"github.com/stretchr/testify/require"
)

func TestMsg_KEEPALIVE_JSON(t *testing.T) {
	msg := NewMsg()
	msg.Dir = dir.DIR_R
	msg.Seq = 2
	msg.Time = time.Date(2025, 7, 11, 8, 47, 22, 659000000, time.UTC)
	msg.Type = KEEPALIVE
	msg.Upper = KEEPALIVE

	j := msg.GetJSON()
	s := string(j)
	require.Contains(t, s, `"R"`)
	require.Contains(t, s, `"KEEPALIVE"`)
	require.Contains(t, s, `null`)
}

func TestMsg_Type_Strings(t *testing.T) {
	// verify type names match documentation
	require.Equal(t, "OPEN", OPEN.String())
	require.Equal(t, "UPDATE", UPDATE.String())
	require.Equal(t, "NOTIFY", NOTIFY.String())
	require.Equal(t, "KEEPALIVE", KEEPALIVE.String())
	require.Equal(t, "REFRESH", REFRESH.String())
}

func TestOpen_JSON(t *testing.T) {
	msg := NewMsg()
	msg.Open.Init(msg)
	msg.Open.Version = 4
	msg.Open.ASN = 65055
	msg.Open.Identifier = netip.MustParseAddr("192.0.2.1")
	msg.Open.HoldTime = 180
	msg.Open.Caps.Init()

	mp := msg.Open.Caps.Use(caps.CAP_MP).(*caps.MP)
	mp.Add(1, 1) // IPv4 unicast

	as4 := msg.Open.Caps.Use(caps.CAP_AS4).(*caps.AS4)
	as4.ASN = 65055

	buf := msg.Open.ToJSON(nil)
	s := string(buf)

	require.Contains(t, s, `"bgp":4`)
	require.Contains(t, s, `"asn":65055`)
	require.Contains(t, s, `"id":"192.0.2.1"`)
	require.Contains(t, s, `"hold":180`)
	require.Contains(t, s, `"caps":{`)
	require.Contains(t, s, `"MP":["IPV4/UNICAST"]`)
	require.Contains(t, s, `"AS4":65055`)

	// round-trip
	msg2 := NewMsg()
	msg2.Open.Init(msg2)
	msg2.Open.Caps.Init()
	err := msg2.Open.FromJSON(buf)
	require.NoError(t, err)
	require.Equal(t, byte(4), msg2.Open.Version)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), msg2.Open.Identifier)
	require.Equal(t, uint16(180), msg2.Open.HoldTime)
}

func mustPrefix(s string) nlri.Prefix {
	p, err := nlri.FromString(s)
	if err != nil {
		panic(err)
	}
	return p
}

func TestUpdate_Reach_JSON(t *testing.T) {
	msg := NewMsg()
	msg.Update.Init(msg)
	msg.Update.Reach = []nlri.Prefix{
		mustPrefix("8.8.8.0/24"),
		mustPrefix("8.8.4.0/24"),
	}

	buf := msg.Update.ToJSON(nil)
	s := string(buf)
	require.Contains(t, s, `"reach":["8.8.8.0/24","8.8.4.0/24"]`)

	// round-trip
	msg2 := NewMsg()
	msg2.Update.Init(msg2)
	err := msg2.Update.FromJSON(buf)
	require.NoError(t, err)
	require.Len(t, msg2.Update.Reach, 2)
}

func TestUpdate_Unreach_JSON(t *testing.T) {
	msg := NewMsg()
	msg.Update.Init(msg)
	msg.Update.Unreach = []nlri.Prefix{
		mustPrefix("10.0.0.0/8"),
	}

	buf := msg.Update.ToJSON(nil)
	s := string(buf)
	require.Contains(t, s, `"unreach":["10.0.0.0/8"]`)

	msg2 := NewMsg()
	msg2.Update.Init(msg2)
	err := msg2.Update.FromJSON(buf)
	require.NoError(t, err)
	require.Len(t, msg2.Update.Unreach, 1)
}

func TestUpdate_Empty_JSON(t *testing.T) {
	msg := NewMsg()
	msg.Update.Init(msg)

	buf := msg.Update.ToJSON(nil)
	require.Equal(t, "{}", string(buf))
}
