package graph

import (
	"math"
	"sort"
)

// LayoutAlgorithm defines the interface for graph layout algorithms
type LayoutAlgorithm interface {
	// Layout computes positions for all nodes in the graph.
	// It sets X, Y, Width, Height on each node and returns the total canvas Width and Height.
	Layout(nodes map[string]*DagNode, edges []DagEdge) (width, height int)
}

// LayoutConfig holds common configuration for layout algorithms
type LayoutConfig struct {
	NodeWidth  int
	NodeHeight int
	MinWidth   int
	MinHeight  int
	Padding    int // margin around the entire graph
}

// DefaultLayoutConfig returns sensible defaults for layout
func DefaultLayoutConfig() LayoutConfig {
	return LayoutConfig{
		NodeWidth:  180,
		NodeHeight: 60,
		MinWidth:   400,
		MinHeight:  200,
		Padding:    40,
	}
}

// =============================================================================
// Hierarchical Layout (existing algorithm, refactored)
// =============================================================================

// HierarchicalLayout arranges nodes in layers based on graph depth (BFS from roots)
type HierarchicalLayout struct {
	Config       LayoutConfig
	LayerSpacing int // vertical space between layers
	NodeSpacing  int // horizontal space between nodes in same layer
}

// NewHierarchicalLayout creates a new hierarchical layout with default settings
func NewHierarchicalLayout() *HierarchicalLayout {
	return &HierarchicalLayout{
		Config:       DefaultLayoutConfig(),
		LayerSpacing: 120,
		NodeSpacing:  40,
	}
}

func (h *HierarchicalLayout) Layout(nodes map[string]*DagNode, edges []DagEdge) (width, height int) {
	if len(nodes) == 0 {
		return h.Config.MinWidth, h.Config.MinHeight
	}

	// Find root nodes (nodes with no incoming edges)
	hasIncoming := make(map[string]bool)
	for _, edge := range edges {
		hasIncoming[edge.To] = true
	}

	var roots []string
	for id := range nodes {
		if !hasIncoming[id] {
			roots = append(roots, id)
		}
	}
	sort.Strings(roots)

	// Build adjacency list
	children := make(map[string][]string)
	for _, edge := range edges {
		children[edge.From] = append(children[edge.From], edge.To)
	}

	// BFS to assign layers
	layers := make(map[string]int)
	queue := make([]string, 0, len(nodes))
	for _, root := range roots {
		layers[root] = 0
		queue = append(queue, root)
	}

	for len(queue) > 0 {
		nodeID := queue[0]
		queue = queue[1:]
		currentLayer := layers[nodeID]

		childList := children[nodeID]
		sort.Strings(childList)
		for _, childID := range childList {
			if _, assigned := layers[childID]; !assigned {
				layers[childID] = currentLayer + 1
				queue = append(queue, childID)
			}
		}
	}

	// Handle orphan nodes
	for id := range nodes {
		if _, ok := layers[id]; !ok {
			layers[id] = 0
		}
	}

	// Group by layer
	layerNodes := make(map[int][]*DagNode)
	maxLayer := 0
	for id, layer := range layers {
		layerNodes[layer] = append(layerNodes[layer], nodes[id])
		if layer > maxLayer {
			maxLayer = layer
		}
	}

	// Sort nodes within each layer for consistent ordering
	for layer := range layerNodes {
		sort.Slice(layerNodes[layer], func(i, j int) bool {
			return layerNodes[layer][i].ID < layerNodes[layer][j].ID
		})
	}

	// Calculate positions
	maxNodesInLayer := 0
	for _, layerNodeList := range layerNodes {
		if len(layerNodeList) > maxNodesInLayer {
			maxNodesInLayer = len(layerNodeList)
		}
	}

	for layer := 0; layer <= maxLayer; layer++ {
		layerNodeList := layerNodes[layer]
		y := h.Config.Padding + layer*(h.Config.NodeHeight+h.LayerSpacing)

		for i, node := range layerNodeList {
			node.X = h.Config.Padding + i*(h.Config.NodeWidth+h.NodeSpacing)
			node.Y = y
			node.Width = h.Config.NodeWidth
			node.Height = h.Config.NodeHeight
		}
	}

	width = h.Config.Padding*2 + maxNodesInLayer*(h.Config.NodeWidth+h.NodeSpacing)
	if width < h.Config.MinWidth {
		width = h.Config.MinWidth
	}
	height = h.Config.Padding*2 + (maxLayer+1)*(h.Config.NodeHeight+h.LayerSpacing)
	if height < h.Config.MinHeight {
		height = h.Config.MinHeight
	}

	return width, height
}

// =============================================================================
// Force-Directed Layout
// =============================================================================

// ForceDirectedLayout uses physics simulation to position nodes
type ForceDirectedLayout struct {
	Config          LayoutConfig
	Iterations      int     // number of simulation steps
	RepulsionForce  float64 // strength of node-node repulsion
	AttractionForce float64 // strength of edge attraction
	Damping         float64 // velocity damping per iteration
	IdealEdgeLength float64 // target length for edges
}

// NewForceDirectedLayout creates a new force-directed layout with default settings
func NewForceDirectedLayout() *ForceDirectedLayout {
	config := DefaultLayoutConfig()
	// Calculate ideal edge length based on node diagonal
	nodeDiag := math.Sqrt(float64(config.NodeWidth*config.NodeWidth + config.NodeHeight*config.NodeHeight))
	return &ForceDirectedLayout{
		Config:          config,
		Iterations:      300,
		RepulsionForce:  12000.0,
		AttractionForce: 0.05,
		Damping:         0.85,
		IdealEdgeLength: nodeDiag * 1.5, // Ideal edge length based on node size
	}
}

// forceNode holds simulation state for a node
type forceNode struct {
	node   *DagNode
	x, y   float64
	vx, vy float64
	fx, fy float64
	pinned bool
}

func (f *ForceDirectedLayout) Layout(nodes map[string]*DagNode, edges []DagEdge) (width, height int) {
	if len(nodes) == 0 {
		return f.Config.MinWidth, f.Config.MinHeight
	}

	// Initialize simulation nodes with initial positions
	simNodes := make(map[string]*forceNode)
	nodeList := make([]*forceNode, 0, len(nodes))

	// Use hierarchical layout for initial positions (helps convergence)
	initialLayout := NewHierarchicalLayout()
	initialLayout.Layout(nodes, edges)

	for id, node := range nodes {
		fn := &forceNode{
			node: node,
			x:    float64(node.X + node.Width/2),
			y:    float64(node.Y + node.Height/2),
		}
		simNodes[id] = fn
		nodeList = append(nodeList, fn)
	}

	// Build edge lookup for attraction forces
	edgeList := make([][2]*forceNode, 0, len(edges))
	for _, edge := range edges {
		if from, ok := simNodes[edge.From]; ok {
			if to, ok := simNodes[edge.To]; ok {
				edgeList = append(edgeList, [2]*forceNode{from, to})
			}
		}
	}

	// Run simulation
	for iter := 0; iter < f.Iterations; iter++ {
		// Reset forces
		for _, fn := range nodeList {
			fn.fx = 0
			fn.fy = 0
		}

		// Repulsion forces (all pairs)
		for i := 0; i < len(nodeList); i++ {
			for j := i + 1; j < len(nodeList); j++ {
				f.applyRepulsion(nodeList[i], nodeList[j])
			}
		}

		// Attraction forces (edges)
		for _, edge := range edgeList {
			f.applyAttraction(edge[0], edge[1])
		}

		// Center gravity (gentle pull toward center to prevent drift)
		centerX, centerY := f.computeCenter(nodeList)
		for _, fn := range nodeList {
			fn.fx += (centerX - fn.x) * 0.01
			fn.fy += (centerY - fn.y) * 0.01
		}

		// Update velocities and positions
		for _, fn := range nodeList {
			if fn.pinned {
				continue
			}
			fn.vx = (fn.vx + fn.fx) * f.Damping
			fn.vy = (fn.vy + fn.fy) * f.Damping

			// Limit max velocity
			maxVel := 50.0
			vel := math.Sqrt(fn.vx*fn.vx + fn.vy*fn.vy)
			if vel > maxVel {
				fn.vx = fn.vx / vel * maxVel
				fn.vy = fn.vy / vel * maxVel
			}

			fn.x += fn.vx
			fn.y += fn.vy
		}
	}

	// Calculate bounding box and normalize positions
	minX, minY := math.MaxFloat64, math.MaxFloat64
	maxX, maxY := -math.MaxFloat64, -math.MaxFloat64

	for _, fn := range nodeList {
		if fn.x < minX {
			minX = fn.x
		}
		if fn.y < minY {
			minY = fn.y
		}
		if fn.x > maxX {
			maxX = fn.x
		}
		if fn.y > maxY {
			maxY = fn.y
		}
	}

	// Translate to positive coordinates with padding
	offsetX := float64(f.Config.Padding) - minX + float64(f.Config.NodeWidth)/2
	offsetY := float64(f.Config.Padding) - minY + float64(f.Config.NodeHeight)/2

	for _, fn := range nodeList {
		fn.node.X = int(fn.x + offsetX - float64(f.Config.NodeWidth)/2)
		fn.node.Y = int(fn.y + offsetY - float64(f.Config.NodeHeight)/2)
		fn.node.Width = f.Config.NodeWidth
		fn.node.Height = f.Config.NodeHeight
	}

	// Calculate canvas size
	width = int(maxX-minX) + f.Config.NodeWidth + f.Config.Padding*2
	height = int(maxY-minY) + f.Config.NodeHeight + f.Config.Padding*2

	if width < f.Config.MinWidth {
		width = f.Config.MinWidth
	}
	if height < f.Config.MinHeight {
		height = f.Config.MinHeight
	}

	return width, height
}

func (f *ForceDirectedLayout) applyRepulsion(a, b *forceNode) {
	dx := a.x - b.x
	dy := a.y - b.y
	dist := math.Sqrt(dx*dx + dy*dy)

	// Calculate minimum distance based on node dimensions
	// Nodes should not overlap, so minimum distance is based on node size
	nodeWidth := float64(f.Config.NodeWidth)
	nodeHeight := float64(f.Config.NodeHeight)
	// Use diagonal as the effective radius for each node
	nodeRadius := math.Sqrt(nodeWidth*nodeWidth+nodeHeight*nodeHeight) / 2
	minDist := nodeRadius * 2.2 // 2 radii + some padding

	// If nodes are overlapping or very close, apply strong separation force
	if dist < minDist {
		// Strong repulsion when overlapping
		if dist < 1 {
			dist = 1
			// Random nudge to separate coincident nodes
			dx = (float64(len(a.node.ID)%10) - 5) * 0.1
			dy = (float64(len(b.node.ID)%10) - 5) * 0.1
		}
		force := f.RepulsionForce * (minDist - dist) / dist * 0.5
		fx := force * dx / dist
		fy := force * dy / dist
		a.fx += fx
		a.fy += fy
		b.fx -= fx
		b.fy -= fy
		return
	}

	// Normal Coulomb repulsion for non-overlapping nodes
	// Coulomb's law: F = k / d^2
	force := f.RepulsionForce / (dist * dist)

	fx := force * dx / dist
	fy := force * dy / dist

	a.fx += fx
	a.fy += fy
	b.fx -= fx
	b.fy -= fy
}

func (f *ForceDirectedLayout) applyAttraction(a, b *forceNode) {
	dx := b.x - a.x
	dy := b.y - a.y
	dist := math.Sqrt(dx*dx + dy*dy)

	if dist < 1 {
		dist = 1
	}

	// Calculate ideal edge length accounting for node dimensions
	nodeWidth := float64(f.Config.NodeWidth)
	nodeHeight := float64(f.Config.NodeHeight)
	nodeRadius := math.Sqrt(nodeWidth*nodeWidth+nodeHeight*nodeHeight) / 2
	// Ideal length should be at least 2 node radii + some spacing
	idealLength := f.IdealEdgeLength + nodeRadius*2

	// Hooke's law: F = k * (d - ideal)
	displacement := dist - idealLength
	force := f.AttractionForce * displacement

	fx := force * dx / dist
	fy := force * dy / dist

	a.fx += fx
	a.fy += fy
	b.fx -= fx
	b.fy -= fy
}

func (f *ForceDirectedLayout) computeCenter(nodes []*forceNode) (float64, float64) {
	if len(nodes) == 0 {
		return 0, 0
	}
	var sumX, sumY float64
	for _, fn := range nodes {
		sumX += fn.x
		sumY += fn.y
	}
	return sumX / float64(len(nodes)), sumY / float64(len(nodes))
}

// =============================================================================
// Hierarchical Force Layout (hybrid approach)
// =============================================================================

// HierarchicalForceLayout combines hierarchical layering with subtree-based positioning.
// Children are positioned directly below their parents, with subtree widths calculated
// to prevent overlap.
type HierarchicalForceLayout struct {
	Config       LayoutConfig
	LayerSpacing int
	NodeSpacing  int
}

// NewHierarchicalForceLayout creates a hybrid layout
func NewHierarchicalForceLayout() *HierarchicalForceLayout {
	return &HierarchicalForceLayout{
		Config:       DefaultLayoutConfig(),
		LayerSpacing: 100,
		NodeSpacing:  30,
	}
}

func (h *HierarchicalForceLayout) Layout(nodes map[string]*DagNode, edges []DagEdge) (width, height int) {
	if len(nodes) == 0 {
		return h.Config.MinWidth, h.Config.MinHeight
	}

	// Build adjacency lists
	children := make(map[string][]string)
	parents := make(map[string][]string)
	hasIncoming := make(map[string]bool)

	for _, edge := range edges {
		children[edge.From] = append(children[edge.From], edge.To)
		parents[edge.To] = append(parents[edge.To], edge.From)
		hasIncoming[edge.To] = true
	}

	// Find roots (nodes with no incoming edges)
	var roots []string
	for id := range nodes {
		if !hasIncoming[id] {
			roots = append(roots, id)
		}
	}
	sort.Strings(roots)

	// Assign layers using BFS
	layers := make(map[string]int)
	queue := make([]string, 0, len(nodes))
	for _, root := range roots {
		layers[root] = 0
		queue = append(queue, root)
	}

	for len(queue) > 0 {
		nodeID := queue[0]
		queue = queue[1:]
		currentLayer := layers[nodeID]

		childList := children[nodeID]
		sort.Strings(childList)
		for _, childID := range childList {
			if _, assigned := layers[childID]; !assigned {
				layers[childID] = currentLayer + 1
				queue = append(queue, childID)
			}
		}
	}

	// Handle orphan nodes
	for id := range nodes {
		if _, ok := layers[id]; !ok {
			layers[id] = 0
		}
	}

	// Find max layer
	maxLayer := 0
	for _, layer := range layers {
		if layer > maxLayer {
			maxLayer = layer
		}
	}

	// Track which nodes have been positioned (for shared children in DAG)
	positioned := make(map[string]bool)
	nodeX := make(map[string]float64)

	// Calculate subtree width for each node (memoized)
	subtreeWidth := make(map[string]float64)
	var calcSubtreeWidth func(nodeID string) float64
	calcSubtreeWidth = func(nodeID string) float64 {
		if w, ok := subtreeWidth[nodeID]; ok {
			return w
		}

		childList := children[nodeID]
		if len(childList) == 0 {
			subtreeWidth[nodeID] = float64(h.Config.NodeWidth)
			return subtreeWidth[nodeID]
		}

		// Sort children for consistent ordering
		sort.Strings(childList)

		// Sum up children's subtree widths
		totalChildWidth := 0.0
		for i, childID := range childList {
			totalChildWidth += calcSubtreeWidth(childID)
			if i > 0 {
				totalChildWidth += float64(h.NodeSpacing)
			}
		}

		// Subtree width is max of node width and children's total width
		nodeWidth := float64(h.Config.NodeWidth)
		if totalChildWidth > nodeWidth {
			subtreeWidth[nodeID] = totalChildWidth
		} else {
			subtreeWidth[nodeID] = nodeWidth
		}
		return subtreeWidth[nodeID]
	}

	// Calculate subtree widths for all nodes
	for id := range nodes {
		calcSubtreeWidth(id)
	}

	// Position nodes using DFS from roots
	var positionSubtree func(nodeID string, xStart float64)
	positionSubtree = func(nodeID string, xStart float64) {
		if positioned[nodeID] {
			return
		}
		positioned[nodeID] = true

		// Center this node within its subtree width
		sw := subtreeWidth[nodeID]
		nodeX[nodeID] = xStart + sw/2 - float64(h.Config.NodeWidth)/2

		// Position children
		childList := children[nodeID]
		if len(childList) == 0 {
			return
		}
		sort.Strings(childList)

		// Calculate starting X for children to be centered under parent
		totalChildWidth := 0.0
		for i, childID := range childList {
			totalChildWidth += subtreeWidth[childID]
			if i > 0 {
				totalChildWidth += float64(h.NodeSpacing)
			}
		}

		// Start children centered under the parent
		parentCenterX := xStart + sw/2
		childStartX := parentCenterX - totalChildWidth/2

		currentX := childStartX
		for _, childID := range childList {
			if !positioned[childID] {
				positionSubtree(childID, currentX)
			}
			currentX += subtreeWidth[childID] + float64(h.NodeSpacing)
		}
	}

	// Position each root's subtree
	currentX := float64(h.Config.Padding)
	for _, root := range roots {
		positionSubtree(root, currentX)
		currentX += subtreeWidth[root] + float64(h.NodeSpacing)*2
	}

	// Handle nodes with multiple parents (already positioned, but need to adjust)
	// For DAG nodes with multiple parents, use average of parent positions
	for layer := 1; layer <= maxLayer; layer++ {
		for id, l := range layers {
			if l != layer {
				continue
			}
			parentList := parents[id]
			if len(parentList) > 1 && positioned[id] {
				// Node has multiple parents - reposition to average
				var sumX float64
				var count int
				for _, parentID := range parentList {
					if x, ok := nodeX[parentID]; ok {
						sumX += x + float64(h.Config.NodeWidth)/2
						count++
					}
				}
				if count > 0 {
					// Center under parents' average position
					avgParentCenter := sumX / float64(count)
					nodeX[id] = avgParentCenter - float64(h.Config.NodeWidth)/2
				}
			}
		}
	}

	// Apply positions to nodes
	maxX := 0.0
	for id, node := range nodes {
		x := nodeX[id]
		if x < float64(h.Config.Padding) {
			x = float64(h.Config.Padding)
		}
		node.X = int(x)
		node.Y = h.Config.Padding + layers[id]*(h.Config.NodeHeight+h.LayerSpacing)
		node.Width = h.Config.NodeWidth
		node.Height = h.Config.NodeHeight

		if x+float64(h.Config.NodeWidth) > maxX {
			maxX = x + float64(h.Config.NodeWidth)
		}
	}

	width = int(maxX) + h.Config.Padding
	height = h.Config.Padding*2 + (maxLayer+1)*(h.Config.NodeHeight+h.LayerSpacing)

	if width < h.Config.MinWidth {
		width = h.Config.MinWidth
	}
	if height < h.Config.MinHeight {
		height = h.Config.MinHeight
	}

	return width, height
}
