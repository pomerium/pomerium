package graph

// LayoutType represents the available layout algorithms
type LayoutType string

const (
	LayoutHierarchical      LayoutType = "hierarchical"
	LayoutForceDirected     LayoutType = "force"
	LayoutHierarchicalForce LayoutType = "hybrid"
)

// getLayoutAlgorithm returns the appropriate layout algorithm based on type
func GetLayoutAlgorithm(layoutType LayoutType) LayoutAlgorithm {
	switch layoutType {
	case LayoutForceDirected:
		return NewForceDirectedLayout()
	case LayoutHierarchicalForce:
		return NewHierarchicalForceLayout()
	default:
		return NewHierarchicalLayout()
	}
}

// dagNode represents a node in the channelz DAG
type DagNode struct {
	ID        string
	Type      string // "channel", "subchannel", "socket", "server"
	Label     string
	State     string
	Target    string
	X, Y      int
	Width     int
	Height    int
	DetailURL string
}

// dagEdge represents a connection between nodes
type DagEdge struct {
	From string
	To   string
}

// dagGraph holds the complete graph data
type DagGraph struct {
	Nodes  map[string]*DagNode
	Edges  []DagEdge
	Width  int
	Height int
}

// dagStats holds summary statistics
type DagStats struct {
	TotalChannels    int
	TotalSubchannels int
	TotalSockets     int
	TotalServers     int
	Ready            int
	Connecting       int
	Idle             int
	Failed           int
	Shutdown         int
}

func (s *DagStats) updateStateCount(state string) {
	switch state {
	case "READY":
		s.Ready++
	case "CONNECTING":
		s.Connecting++
	case "IDLE":
		s.Idle++
	case "TRANSIENT_FAILURE":
		s.Failed++
	case "SHUTDOWN":
		s.Shutdown++
	}
}
