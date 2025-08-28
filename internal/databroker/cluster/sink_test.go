package cluster_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/databroker/cluster"
)

func TestSink(t *testing.T) {
	t.Parallel()

	var sink cluster.Sink[int]

	ch1 := sink.Bind()
	assert.Len(t, ch1, 0, "should not send the zero value")
	sink.Unbind(ch1)

	for i := range 10 {
		sink.Send(i)
	}

	ch2 := sink.Bind()
	if assert.Len(t, ch2, 1, "should send the last value immediately") {
		assert.Equal(t, 9, <-ch2)
	}

	sink.Send(10)
	if assert.Len(t, ch2, 1, "should send new values") {
		assert.Equal(t, 10, <-ch2)
	}
	sink.Unbind(ch2)
	sink.Send(11)
	assert.Len(t, ch2, 0, "should not send new values")
}
