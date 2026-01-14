package graph

// svgNodeData is used for template rendering
type SvgNodeData struct {
	X          int
	Y          int
	Width      int
	Height     int
	TextX      int
	TypeLabel  string
	Label      string
	State      string
	StateClass string
	DetailURL  string
}

// svgEdgeData is used for template rendering
type SvgEdgeData struct {
	X1, Y1, X2, Y2 int
}
