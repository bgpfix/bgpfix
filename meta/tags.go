package meta

import (
	"slices"
	"strings"
)

// Tag is a message tag: a key with a non-empty value
type Tag struct {
	Key, Val string
}

// Tags are message tags, sorted by key
type Tags []Tag

func tagCmp(t Tag, key string) int { return strings.Compare(t.Key, key) }

// Get returns the value of key, or "" if not set
func (tags Tags) Get(key string) string {
	if i, ok := slices.BinarySearchFunc(tags, key, tagCmp); ok {
		return tags[i].Val
	}
	return ""
}

// Set sets key to val; an empty val drops key
func (tags *Tags) Set(key, val string) {
	i, ok := slices.BinarySearchFunc(*tags, key, tagCmp)
	switch {
	case ok && val == "":
		*tags = slices.Delete(*tags, i, i+1)
	case ok:
		(*tags)[i].Val = val
	case val != "":
		*tags = slices.Insert(*tags, i, Tag{key, val})
	}
}
