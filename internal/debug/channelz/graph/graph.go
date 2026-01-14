package graph

import (
	"fmt"
	"sort"

	"google.golang.org/grpc/channelz/grpc_channelz_v1"
)

func stateToClass(state string) string {
	switch state {
	case "READY":
		return "ready"
	case "CONNECTING":
		return "connecting"
	case "IDLE":
		return "idle"
	case "TRANSIENT_FAILURE":
		return "failure"
	case "SHUTDOWN":
		return "shutdown"
	default:
		return "neutral"
	}
}

func newDagGraph() *DagGraph {
	return &DagGraph{
		Nodes: make(map[string]*DagNode),
		Edges: []DagEdge{},
	}
}

func (g *DagGraph) addNode(node *DagNode) {
	g.Nodes[node.ID] = node
}

func (g *DagGraph) addEdge(from, to string) {
	g.Edges = append(g.Edges, DagEdge{From: from, To: to})
}

func (g *DagGraph) ApplyLayout(layout LayoutAlgorithm) {
	g.Width, g.Height = layout.Layout(g.Nodes, g.Edges)
}

func (g *DagGraph) PrepareSVGNodes() []SvgNodeData {
	nodes := make([]SvgNodeData, 0, len(g.Nodes))
	for _, node := range g.Nodes {
		nodes = append(nodes, SvgNodeData{
			X:          node.X,
			Y:          node.Y,
			Width:      node.Width,
			Height:     node.Height,
			TextX:      node.Width / 2,
			TypeLabel:  node.Type,
			Label:      node.Label,
			State:      node.State,
			StateClass: stateToClass(node.State),
			DetailURL:  node.DetailURL,
		})
	}
	// Sort for consistent rendering order
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Y != nodes[j].Y {
			return nodes[i].Y < nodes[j].Y
		}
		return nodes[i].X < nodes[j].X
	})
	return nodes
}

func (g *DagGraph) CalculateEdgeCoordinates() []SvgEdgeData {
	edges := make([]SvgEdgeData, 0, len(g.Edges))

	for _, edge := range g.Edges {
		fromNode := g.Nodes[edge.From]
		toNode := g.Nodes[edge.To]

		if fromNode == nil || toNode == nil {
			continue
		}

		// Draw from bottom-center of source to top-center of target
		edges = append(edges, SvgEdgeData{
			X1: fromNode.X + fromNode.Width/2,
			Y1: fromNode.Y + fromNode.Height,
			X2: toNode.X + toNode.Width/2,
			Y2: toNode.Y,
		})
	}

	return edges
}

// ChannelZData holds pre-fetched channelz data for graph construction
type ChannelZData struct {
	TopChannels []*grpc_channelz_v1.Channel
	Channels    map[int64]*grpc_channelz_v1.Channel
	Subchannels map[int64]*grpc_channelz_v1.Subchannel
	Sockets     map[int64]*grpc_channelz_v1.Socket
	Servers     []*grpc_channelz_v1.Server
}

// NewChannelZData creates a new ChannelZData with initialized maps
func NewChannelZData() *ChannelZData {
	return &ChannelZData{
		Channels:    make(map[int64]*grpc_channelz_v1.Channel),
		Subchannels: make(map[int64]*grpc_channelz_v1.Subchannel),
		Sockets:     make(map[int64]*grpc_channelz_v1.Socket),
	}
}

// FromChannelZData builds a DAG graph from pre-fetched channelz data
func FromChannelZData(data *ChannelZData) (*DagGraph, *DagStats) {
	graph := newDagGraph()
	stats := &DagStats{}

	// Process top channels (entry points)
	for _, ch := range data.TopChannels {
		processChannelFromData(data, graph, stats, ch, "")
	}

	// Process servers
	for _, s := range data.Servers {
		processServerFromData(graph, stats, s)
	}

	return graph, stats
}

func processChannelFromData(data *ChannelZData, graph *DagGraph, stats *DagStats, ch *grpc_channelz_v1.Channel, parentID string) {
	nodeID := fmt.Sprintf("channel-%d", ch.GetRef().GetChannelId())

	// Avoid processing the same channel twice
	if _, exists := graph.Nodes[nodeID]; exists {
		if parentID != "" {
			graph.addEdge(parentID, nodeID)
		}
		return
	}

	state := ch.GetData().GetState().GetState().String()

	label := ch.GetRef().GetName()
	if label == "" {
		label = ch.GetData().GetTarget()
	}

	node := &DagNode{
		ID:        nodeID,
		Type:      "channel",
		Label:     truncateLabel(label, 22),
		State:     state,
		Target:    ch.GetData().GetTarget(),
		DetailURL: fmt.Sprintf("/channelz/channel/%d?view=card", ch.GetRef().GetChannelId()),
	}
	graph.addNode(node)
	if parentID != "" {
		graph.addEdge(parentID, nodeID)
	}
	stats.TotalChannels++
	stats.updateStateCount(state)

	// Process subchannels
	for _, subRef := range ch.GetSubchannelRef() {
		if sub, ok := data.Subchannels[subRef.GetSubchannelId()]; ok {
			processSubchannelFromData(data, graph, stats, sub, nodeID)
		}
	}

	// Process child channels
	for _, chRef := range ch.GetChannelRef() {
		if childCh, ok := data.Channels[chRef.GetChannelId()]; ok {
			processChannelFromData(data, graph, stats, childCh, nodeID)
		}
	}

	// Process sockets
	for _, sockRef := range ch.GetSocketRef() {
		processSocketRefFromData(graph, stats, sockRef, nodeID)
	}
}

func processSocketRefFromData(graph *DagGraph, stats *DagStats, sockRef *grpc_channelz_v1.SocketRef, parentID string) {
	nodeID := fmt.Sprintf("socket-%d", sockRef.GetSocketId())

	// Check if socket already added (can be referenced by multiple parents)
	if _, exists := graph.Nodes[nodeID]; exists {
		graph.addEdge(parentID, nodeID)
		return
	}

	label := sockRef.GetName()
	if label == "" {
		label = fmt.Sprintf("socket-%d", sockRef.GetSocketId())
	}

	node := &DagNode{
		ID:        nodeID,
		Type:      "socket",
		Label:     truncateLabel(label, 22),
		State:     "", // sockets don't have state
		DetailURL: fmt.Sprintf("/channelz/socket/%d?view=card", sockRef.GetSocketId()),
	}
	graph.addNode(node)
	graph.addEdge(parentID, nodeID)
	stats.TotalSockets++
}

func processSubchannelFromData(data *ChannelZData, graph *DagGraph, stats *DagStats, sub *grpc_channelz_v1.Subchannel, parentID string) {
	nodeID := fmt.Sprintf("subchannel-%d", sub.GetRef().GetSubchannelId())

	// Avoid processing the same subchannel twice
	if _, exists := graph.Nodes[nodeID]; exists {
		graph.addEdge(parentID, nodeID)
		return
	}

	state := sub.GetData().GetState().GetState().String()

	label := sub.GetRef().GetName()
	if label == "" {
		label = sub.GetData().GetTarget()
	}

	node := &DagNode{
		ID:        nodeID,
		Type:      "subchannel",
		Label:     truncateLabel(label, 22),
		State:     state,
		Target:    sub.GetData().GetTarget(),
		DetailURL: fmt.Sprintf("/channelz/subchannel/%d?view=card", sub.GetRef().GetSubchannelId()),
	}
	graph.addNode(node)
	graph.addEdge(parentID, nodeID)
	stats.TotalSubchannels++
	stats.updateStateCount(state)

	// Process nested subchannels
	for _, subRef := range sub.GetSubchannelRef() {
		if nestedSub, ok := data.Subchannels[subRef.GetSubchannelId()]; ok {
			processSubchannelFromData(data, graph, stats, nestedSub, nodeID)
		}
	}

	// Process sockets
	for _, sockRef := range sub.GetSocketRef() {
		processSocketRefFromData(graph, stats, sockRef, nodeID)
	}
}

func processServerFromData(graph *DagGraph, stats *DagStats, s *grpc_channelz_v1.Server) {
	nodeID := fmt.Sprintf("server-%d", s.GetRef().GetServerId())

	label := s.GetRef().GetName()
	if label == "" {
		label = fmt.Sprintf("server-%d", s.GetRef().GetServerId())
	}

	node := &DagNode{
		ID:        nodeID,
		Type:      "server",
		Label:     truncateLabel(label, 22),
		State:     "", // servers don't have connectivity state
		DetailURL: fmt.Sprintf("/channelz/server/%d?view=card", s.GetRef().GetServerId()),
	}
	graph.addNode(node)
	stats.TotalServers++

	// Process listen sockets - servers only have socket refs, not full socket data
	for _, sockRef := range s.GetListenSocket() {
		socketNodeID := fmt.Sprintf("socket-%d", sockRef.GetSocketId())

		// Check if socket already added
		if _, exists := graph.Nodes[socketNodeID]; exists {
			graph.addEdge(nodeID, socketNodeID)
			continue
		}

		label := sockRef.GetName()
		if label == "" {
			label = fmt.Sprintf("socket-%d", sockRef.GetSocketId())
		}

		socketNode := &DagNode{
			ID:        socketNodeID,
			Type:      "socket",
			Label:     truncateLabel(label, 22),
			State:     "",
			DetailURL: fmt.Sprintf("/channelz/socket/%d?view=card", sockRef.GetSocketId()),
		}
		graph.addNode(socketNode)
		graph.addEdge(nodeID, socketNodeID)
		stats.TotalSockets++
	}
}
