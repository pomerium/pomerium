package graph

import "testing"

// Helper to create a simple node
func makeNode(id string) *DagNode {
	return &DagNode{ID: id, Type: "channel", Label: id}
}

func TestHierarchicalForceLayout_EmptyGraph(t *testing.T) {
	layout := NewHierarchicalForceLayout()
	nodes := make(map[string]*DagNode)
	edges := []DagEdge{}

	width, height := layout.Layout(nodes, edges)

	if width < layout.Config.MinWidth {
		t.Errorf("width %d should be at least MinWidth %d", width, layout.Config.MinWidth)
	}
	if height < layout.Config.MinHeight {
		t.Errorf("height %d should be at least MinHeight %d", height, layout.Config.MinHeight)
	}
}

func TestHierarchicalForceLayout_SingleNode(t *testing.T) {
	layout := NewHierarchicalForceLayout()
	nodes := map[string]*DagNode{
		"root": makeNode("root"),
	}
	edges := []DagEdge{}

	width, height := layout.Layout(nodes, edges)

	// Node should be positioned
	root := nodes["root"]
	if root.X < layout.Config.Padding {
		t.Errorf("node X %d should be >= padding %d", root.X, layout.Config.Padding)
	}
	if root.Y != layout.Config.Padding {
		t.Errorf("node Y %d should equal padding %d (layer 0)", root.Y, layout.Config.Padding)
	}
	if root.Width != layout.Config.NodeWidth {
		t.Errorf("node width %d should equal NodeWidth %d", root.Width, layout.Config.NodeWidth)
	}
	if root.Height != layout.Config.NodeHeight {
		t.Errorf("node height %d should equal NodeHeight %d", root.Height, layout.Config.NodeHeight)
	}
	if width < root.X+root.Width {
		t.Errorf("canvas width %d should contain node ending at %d", width, root.X+root.Width)
	}
	if height < root.Y+root.Height {
		t.Errorf("canvas height %d should contain node ending at %d", height, root.Y+root.Height)
	}
}

func TestHierarchicalForceLayout_LinearChain(t *testing.T) {
	layout := NewHierarchicalForceLayout()
	nodes := map[string]*DagNode{
		"a": makeNode("a"),
		"b": makeNode("b"),
		"c": makeNode("c"),
	}
	edges := []DagEdge{
		{From: "a", To: "b"},
		{From: "b", To: "c"},
	}

	layout.Layout(nodes, edges)

	// Verify hierarchical ordering: a above b above c
	if nodes["a"].Y >= nodes["b"].Y {
		t.Errorf("node a (Y=%d) should be above node b (Y=%d)", nodes["a"].Y, nodes["b"].Y)
	}
	if nodes["b"].Y >= nodes["c"].Y {
		t.Errorf("node b (Y=%d) should be above node c (Y=%d)", nodes["b"].Y, nodes["c"].Y)
	}

	// Verify layer spacing
	expectedSpacing := layout.Config.NodeHeight + layout.LayerSpacing
	if nodes["b"].Y-nodes["a"].Y != expectedSpacing {
		t.Errorf("layer spacing between a and b: got %d, want %d", nodes["b"].Y-nodes["a"].Y, expectedSpacing)
	}
}

func TestHierarchicalForceLayout_TreeStructure(t *testing.T) {
	layout := NewHierarchicalForceLayout()
	//     root
	//    /    \
	//   a      b
	nodes := map[string]*DagNode{
		"root": makeNode("root"),
		"a":    makeNode("a"),
		"b":    makeNode("b"),
	}
	edges := []DagEdge{
		{From: "root", To: "a"},
		{From: "root", To: "b"},
	}

	layout.Layout(nodes, edges)

	// Root should be above children
	if nodes["root"].Y >= nodes["a"].Y {
		t.Errorf("root (Y=%d) should be above a (Y=%d)", nodes["root"].Y, nodes["a"].Y)
	}
	if nodes["root"].Y >= nodes["b"].Y {
		t.Errorf("root (Y=%d) should be above b (Y=%d)", nodes["root"].Y, nodes["b"].Y)
	}

	// Children should be at the same level
	if nodes["a"].Y != nodes["b"].Y {
		t.Errorf("siblings a (Y=%d) and b (Y=%d) should be at the same Y level", nodes["a"].Y, nodes["b"].Y)
	}
}

func TestHierarchicalForceLayout_MultipleRoots(t *testing.T) {
	layout := NewHierarchicalForceLayout()
	// Two separate trees
	nodes := map[string]*DagNode{
		"root1":  makeNode("root1"),
		"child1": makeNode("child1"),
		"root2":  makeNode("root2"),
		"child2": makeNode("child2"),
	}
	edges := []DagEdge{
		{From: "root1", To: "child1"},
		{From: "root2", To: "child2"},
	}

	layout.Layout(nodes, edges)

	// All roots should be at layer 0
	if nodes["root1"].Y != nodes["root2"].Y {
		t.Errorf("roots should be at same Y level: root1=%d, root2=%d", nodes["root1"].Y, nodes["root2"].Y)
	}

	// Children should be at layer 1
	if nodes["child1"].Y != nodes["child2"].Y {
		t.Errorf("children should be at same Y level: child1=%d, child2=%d", nodes["child1"].Y, nodes["child2"].Y)
	}

	// Trees should not overlap horizontally
	r1Right := nodes["root1"].X + nodes["root1"].Width
	r2Left := nodes["root2"].X
	c1Right := nodes["child1"].X + nodes["child1"].Width
	c2Left := nodes["child2"].X

	// One tree should be entirely to the left of the other
	tree1LeftOfTree2 := r1Right <= r2Left && c1Right <= c2Left
	tree2LeftOfTree1 := nodes["root2"].X+nodes["root2"].Width <= nodes["root1"].X &&
		nodes["child2"].X+nodes["child2"].Width <= nodes["child1"].X

	if !tree1LeftOfTree2 && !tree2LeftOfTree1 {
		t.Errorf("trees should not overlap: root1=[%d,%d], root2=[%d,%d]",
			nodes["root1"].X, r1Right, nodes["root2"].X, nodes["root2"].X+nodes["root2"].Width)
	}
}

func TestHierarchicalForceLayout_DAGWithSharedChild(t *testing.T) {
	layout := NewHierarchicalForceLayout()
	//   a     b
	//    \   /
	//     \ /
	//      c
	nodes := map[string]*DagNode{
		"a": makeNode("a"),
		"b": makeNode("b"),
		"c": makeNode("c"),
	}
	edges := []DagEdge{
		{From: "a", To: "c"},
		{From: "b", To: "c"},
	}

	layout.Layout(nodes, edges)

	// Parents should be above shared child
	if nodes["a"].Y >= nodes["c"].Y {
		t.Errorf("parent a (Y=%d) should be above child c (Y=%d)", nodes["a"].Y, nodes["c"].Y)
	}
	if nodes["b"].Y >= nodes["c"].Y {
		t.Errorf("parent b (Y=%d) should be above child c (Y=%d)", nodes["b"].Y, nodes["c"].Y)
	}

	// Parents should be at the same level
	if nodes["a"].Y != nodes["b"].Y {
		t.Errorf("parents a (Y=%d) and b (Y=%d) should be at the same level", nodes["a"].Y, nodes["b"].Y)
	}

	// Shared child should be positioned (algorithm averages parent positions)
	aCenterX := nodes["a"].X + nodes["a"].Width/2
	bCenterX := nodes["b"].X + nodes["b"].Width/2
	cCenterX := nodes["c"].X + nodes["c"].Width/2
	expectedCenterX := (aCenterX + bCenterX) / 2

	// Allow some tolerance for rounding
	tolerance := 2
	if cCenterX < expectedCenterX-tolerance || cCenterX > expectedCenterX+tolerance {
		t.Errorf("shared child c center X=%d should be near average of parents (%d)", cCenterX, expectedCenterX)
	}
}

func TestHierarchicalForceLayout_OrphanNode(t *testing.T) {
	layout := NewHierarchicalForceLayout()
	// Node with no edges
	nodes := map[string]*DagNode{
		"orphan": makeNode("orphan"),
	}
	edges := []DagEdge{}

	layout.Layout(nodes, edges)

	// Orphan should be placed at layer 0
	if nodes["orphan"].Y != layout.Config.Padding {
		t.Errorf("orphan node Y=%d should be at layer 0 (padding=%d)", nodes["orphan"].Y, layout.Config.Padding)
	}
}

func TestDagStats_UpdateStateCount(t *testing.T) {
	tests := []struct {
		state    string
		field    string
		expected int
	}{
		{"READY", "Ready", 1},
		{"CONNECTING", "Connecting", 1},
		{"IDLE", "Idle", 1},
		{"TRANSIENT_FAILURE", "Failed", 1},
		{"SHUTDOWN", "Shutdown", 1},
		{"UNKNOWN", "", 0}, // Unknown states don't increment anything
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			stats := &DagStats{}
			stats.updateStateCount(tt.state)

			var actual int
			switch tt.field {
			case "Ready":
				actual = stats.Ready
			case "Connecting":
				actual = stats.Connecting
			case "Idle":
				actual = stats.Idle
			case "Failed":
				actual = stats.Failed
			case "Shutdown":
				actual = stats.Shutdown
			default:
				// For unknown states, all should be 0
				if stats.Ready != 0 || stats.Connecting != 0 || stats.Idle != 0 ||
					stats.Failed != 0 || stats.Shutdown != 0 {
					t.Error("unknown state should not increment any counter")
				}
				return
			}

			if actual != tt.expected {
				t.Errorf("stats.%s = %d, want %d", tt.field, actual, tt.expected)
			}
		})
	}
}

func TestDagStats_MultipleUpdates(t *testing.T) {
	stats := &DagStats{}
	stats.updateStateCount("READY")
	stats.updateStateCount("READY")
	stats.updateStateCount("CONNECTING")
	stats.updateStateCount("TRANSIENT_FAILURE")

	if stats.Ready != 2 {
		t.Errorf("Ready = %d, want 2", stats.Ready)
	}
	if stats.Connecting != 1 {
		t.Errorf("Connecting = %d, want 1", stats.Connecting)
	}
	if stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", stats.Failed)
	}
}
