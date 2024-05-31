package writers_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
)

func TestNewForURI(t *testing.T) {
	for _, tc := range []struct {
		uri string
		err string
	}{
		{
			uri: "/foo",
			err: "unknown scheme: \"\"",
		},
		{
			uri: "foo://bar",
			err: "unknown scheme: \"foo\"",
		},
		{
			uri: "foo://\x7f",
			err: "malformed uri: parse \"foo://\\x7f\": net/url: invalid control character in URL",
		},
	} {
		w, err := writers.NewForURI(tc.uri)
		if tc.err == "" {
			assert.NoError(t, err)
			assert.NotNil(t, w)
		} else {
			assert.EqualError(t, err, tc.err)
			assert.Nil(t, w)
		}
	}
}
