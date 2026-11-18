package meta

import "testing"

func TestTags(t *testing.T) {
	var tags Tags
	tags.Set("b", "2")
	tags.Set("a", "1")
	tags.Set("c", "3")
	tags.Set("b", "x")
	tags.Set("c", "")
	tags.Set("d", "")
	if len(tags) != 2 || tags[0] != (Tag{"a", "1"}) || tags[1] != (Tag{"b", "x"}) {
		t.Errorf("tags = %v", tags)
	}
	if tags.Get("a") != "1" || tags.Get("c") != "" || Tags(nil).Get("a") != "" {
		t.Errorf("Get failed")
	}
}
