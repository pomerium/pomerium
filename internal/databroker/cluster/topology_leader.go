package cluster

import (
	"context"
	"math"
)

type topologyLowestNodeIDLeaderElector struct {
	Sink[Topology]
	in TopologySource

	ctx    context.Context
	cancel context.CancelFunc
}

// NewLowestNodeIDLeaderElectorTopologySource creates a Topology Source that elects a node leader
// based on the lowest node id.
func NewLowestNodeIDLeaderElectorTopologySource(in TopologySource) TopologySource {
	src := &topologyLowestNodeIDLeaderElector{in: in}
	src.ctx, src.cancel = context.WithCancel(context.Background())
	go src.run()
	return src
}

func (src *topologyLowestNodeIDLeaderElector) Stop() {
	src.cancel()
}

func (src *topologyLowestNodeIDLeaderElector) run() {
	ch := src.in.Bind()
	defer src.in.Unbind(ch)

	for {
		var in Topology
		select {
		case <-src.ctx.Done():
			return
		case in = <-ch:
		}

		out := Topology{Nodes: make([]Node, len(in.Nodes))}
		if len(out.Nodes) > 0 {
			lowestIdx := 0
			lowestNodeID := uint64(math.MaxUint64)
			for i, n := range in.Nodes {
				if n.NodeID < lowestNodeID {
					lowestIdx = i
					lowestNodeID = n.NodeID
				}
				out.Nodes[i] = n
				out.Nodes[i].IsLeader = false
			}
			out.Nodes[lowestIdx].IsLeader = true
		}
		src.Send(out)
	}
}
