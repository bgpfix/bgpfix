package pipe

import "testing"

// Context.FromJSON must not keep references to the input buffer: readers re-use it
// while the message is still being processed (the tag keys used to alias it).
func TestContextFromJSONNoAlias(t *testing.T) {
	src := []byte(`{"PEER_AS":"65000","COLLECTOR":"rrc00","rov/192.0.2.0/24":"VALID"}`)
	mx := new(Context)
	if err := mx.FromJSON(src); err != nil {
		t.Fatal(err)
	}

	for i := range src {
		src[i] = 'x' // the reader moves on to the next message
	}

	want := map[string]string{"PEER_AS": "65000", "COLLECTOR": "rrc00", "rov/192.0.2.0/24": "VALID"}
	for k, v := range want {
		if got := mx.GetTag(k); got != v {
			t.Errorf("tag %q: got %q, want %q", k, got, v)
		}
	}
	if got := len(mx.GetTags()); got != len(want) {
		t.Errorf("%d tags, want %d: %v", got, len(want), mx.GetTags())
	}
	for k := range mx.GetTags() {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected tag key %q", k)
		}
	}
}

// a feed must not choose how its messages are processed
func TestContextFromJSONIgnoresAction(t *testing.T) {
	mx := new(Context)
	if err := mx.FromJSON([]byte(`{"ACTION":"DROP","A":"1"}`)); err != nil {
		t.Fatal(err)
	}
	if mx.Action != 0 || len(mx.GetTags()) != 1 || mx.GetTag("A") != "1" {
		t.Errorf("action=%v tags=%v", mx.Action, mx.GetTags())
	}
}
