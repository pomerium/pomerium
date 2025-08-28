package cluster_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/databroker/cluster"
)

func TestSinkTopologySource(t *testing.T) {
	t.Parallel()

	t1 := cluster.Topology{
		Nodes: []cluster.Node{{NodeID: 1}},
	}
	t2 := cluster.Topology{
		Nodes: []cluster.Node{{NodeID: 1}, {NodeID: 2}},
	}

	src := cluster.NewSinkTopologySource(t1)
	ch1 := src.Bind()
	if assert.Len(t, ch1, 1) {
		assert.Equal(t, t1, <-ch1)
	}
	src.Send(t2)
	if assert.Len(t, ch1, 1) {
		assert.Equal(t, t2, <-ch1)
	}
	src.Unbind(ch1)
}
