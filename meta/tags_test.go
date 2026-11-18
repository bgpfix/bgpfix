package meta

import "testing"

func TestTags(t *testing.T) {
	var tags Tags
	tags.Set("PEER_IP", "192.0.2.1")
	tags.Set("PEER_AS", "65001")
	tags.Set("LOCAL_AS", "x") // invalid: dropped
	tags.Set("b", "2")
	tags.Set("a", "1")
	tags.Set("b", "")
	if tags.PeerIP.String() != "192.0.2.1" || tags.PeerAS != 65001 || tags.LocalAS != 0 {
		t.Errorf("fields: %+v", tags)
	}
	if tags.Get("PEER_AS") != "65001" || tags.Get("a") != "1" || tags.Get("b") != "" || (*Tags)(nil).Get("a") != "" {
		t.Errorf("Get failed")
	}
	js := string(tags.ToJSON(nil))
	if js != `{"PEER_AS":"65001","PEER_IP":"192.0.2.1","a":"1"}` {
		t.Errorf("json %s", js)
	}
	var t2 Tags
	if err := t2.FromJSON([]byte(js)); err != nil || string(t2.ToJSON(nil)) != js {
		t.Errorf("round-trip: %v %s", err, t2.ToJSON(nil))
	}
	tags.Reset()
	if string(tags.ToJSON(nil)) != "{}" {
		t.Errorf("reset: %s", tags.ToJSON(nil))
	}
}

// FromJSON must not keep references to the input buffer: readers re-use it
func TestTagsFromJSONNoAlias(t *testing.T) {
	src := []byte(`{"PEER_AS":"65000","COLLECTOR":"rrc00","rov/192.0.2.0/24":"VALID"}`)
	var tags Tags
	if err := tags.FromJSON(src); err != nil {
		t.Fatal(err)
	}
	for i := range src {
		src[i] = 'x'
	}
	if js := string(tags.ToJSON(nil)); js != `{"COLLECTOR":"rrc00","PEER_AS":"65000","rov/192.0.2.0/24":"VALID"}` {
		t.Errorf("got %s", js)
	}
}

func BenchmarkTagsToJSON(b *testing.B) {
	var tags Tags
	tags.Set("PEER_IP", "192.0.2.1")
	tags.Set("PEER_AS", "65001")
	tags.Set("LOCAL_IP", "2001:db8::1")
	tags.Set("LOCAL_AS", "6447")
	tags.Set("rov/status", "VALID")
	buf := make([]byte, 0, 1024)
	b.ReportAllocs()
	for b.Loop() {
		buf = tags.ToJSON(buf[:0])
	}
}

// invalid well-known values are dropped, zones too
func TestTagsInvalid(t *testing.T) {
	var tags Tags
	tags.Set("PEER_AS", "4294967296")
	tags.Set("PEER_IP", `fe80::1%bad"zone`)
	if tags.PeerAS != 0 || tags.PeerIP.Zone() != "" || string(tags.ToJSON(nil)) != `{"PEER_IP":"fe80::1"}` {
		t.Errorf("got %s", tags.ToJSON(nil))
	}
}
