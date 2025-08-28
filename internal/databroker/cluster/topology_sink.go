package cluster

// A SinkTopologySource sends any topologies it receives.
// This is primarily used for testing.
type SinkTopologySource interface {
	TopologySource
	Send(topology Topology)
}

type sinkTopologySource struct {
	Sink[Topology]
}

// NewSinkTopologySource creates a new SinkTopologySource.
func NewSinkTopologySource(topology Topology) SinkTopologySource {
	src := &sinkTopologySource{}
	src.Send(topology)
	return src
}

func (src *sinkTopologySource) Stop() {}
