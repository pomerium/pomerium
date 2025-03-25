package trace_test

import (
	"net/url"
	"testing"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
	"github.com/stretchr/testify/assert"
)

func TestPomeriumURLQueryCarrier(t *testing.T) {
	t.Parallel()
	values := url.Values{}
	carrier := trace.PomeriumURLQueryCarrier(values)
	assert.Empty(t, carrier.Get("foo"))
	carrier.Set("foo", "bar")
	assert.Equal(t, url.Values{
		"pomerium_foo": []string{"bar"},
	}, values)
	assert.Equal(t, "bar", carrier.Get("foo"))
	carrier.Set("foo", "bar2")
	assert.Equal(t, url.Values{
		"pomerium_foo": []string{"bar2"},
	}, values)
	assert.Equal(t, "bar2", carrier.Get("foo"))

	assert.Panics(t, func() {
		carrier.Keys()
	})
}
