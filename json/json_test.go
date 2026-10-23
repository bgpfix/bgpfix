package json

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUtf8(t *testing.T) {
	require.Equal(t, `za\u00c5`, string(Utf8(nil, []byte("za\xc5"))))                    // invalid UTF-8: like Ascii
	require.Equal(t, "za\u017c\\\"\\u0001", string(Utf8(nil, []byte("za\u017c\"\x01")))) // valid: kept
}
