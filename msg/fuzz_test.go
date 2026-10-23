package msg

import (
	"testing"

	"github.com/bgpfix/bgpfix/afi"
	"github.com/bgpfix/bgpfix/caps"
	"github.com/bgpfix/bgpfix/meta"
)

func fuzzCaps(flags byte) caps.Caps {
	var cps caps.Caps
	if flags&1 != 0 {
		cps.Use(caps.CAP_AS4)
	}
	if flags&2 != 0 {
		ap := cps.Use(caps.CAP_ADDPATH).(*caps.AddPath)
		for _, as := range []afi.AS{afi.AS_IPV4_UNICAST, afi.AS_IPV6_UNICAST, afi.AS_IPV4_FLOWSPEC, afi.AS_IPV6_FLOWSPEC, afi.AS_IPV4_MULTICAST} {
			ap.Add(as, caps.ADDPATH_BIDIR)
		}
	}
	if flags&4 != 0 {
		cps.Use(caps.CAP_EXTENDED_NEXTHOP)
	}
	if flags&8 != 0 {
		cps.Use(caps.CAP_MP)
	}
	return cps
}

func FuzzMsgWire(f *testing.F) {
	f.Add([]byte{}, byte(0))
	f.Fuzz(func(t *testing.T, data []byte, flags byte) {
		cps := fuzzCaps(flags)
		m := NewMsg()
		if flags&16 != 0 {
			m.Dir = meta.DIR_L
		} else {
			m.Dir = meta.DIR_R
		}
		hdr := make([]byte, HEADLEN, HEADLEN+len(data)+1)
		copy(hdr, BgpMarker)
		l := HEADLEN + len(data) - 1
		hdr[16], hdr[17] = byte(l>>8), byte(l)
		if len(data) == 0 {
			return
		}
		hdr[18] = data[0]
		buf := append(hdr, data[1:]...)
		if _, err := m.FromBytes(buf); err != nil {
			return
		}
		if err := m.Parse(cps); err != nil {
			return
		}
		_ = m.String()
		js := append([]byte(nil), m.GetJSON()...)
		// exercise accessors
		if m.Type == UPDATE {
			u := &m.Update
			u.AllReach()
			u.AllUnreach()
			u.AsPath()
			u.NextHop()
			u.AfiSafi()
		}
		// re-marshal
		m.Edit()
		if err := m.Marshal(cps); err != nil {
			return
		}
		m2 := NewMsg()
		if err := m2.FromJSON(js); err == nil {
			m2.Marshal(cps)
			m2.GetJSON()
		}
	})
}

func FuzzMsgJSON(f *testing.F) {
	f.Add([]byte(`["R",1,"2023-01-01T00:00:00.000","UPDATE",{"reach":["1.0.0.0/8"],"attrs":{"ORIGIN":{"flags":"T","value":"IGP"}}},{}]`), byte(1))
	f.Fuzz(func(t *testing.T, data []byte, flags byte) {
		cps := fuzzCaps(flags)
		m := NewMsg()
		if err := m.FromJSON(data); err != nil {
			return
		}
		m.GetJSON()
		if err := m.Marshal(cps); err != nil {
			return
		}
		raw := make([]byte, 0, m.Len())
		raw = append(raw, BgpMarker...)
		l := m.Len()
		raw = append(raw, byte(l>>8), byte(l), byte(m.Type))
		raw = append(raw, m.Data...)
		m2 := NewMsg()
		if _, err := m2.FromBytes(raw); err == nil {
			m2.Parse(cps)
			m2.GetJSON()
		}
	})
}
