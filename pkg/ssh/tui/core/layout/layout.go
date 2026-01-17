package layout

import (
	"cmp"
	"slices"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
)

type layoutCell struct {
	index  int
	weight int

	// Contains as many entries as the sum of all weights, where each entry is
	// either 0 or 1. The value is the extra width this column should have for
	// any given total (flex) width mod (sum of all weights).
	adjust []int
}

type Cell struct {
	Title    string
	Size     int
	SizeFunc func() int
	// If the layout does not have enough room for all fixed cells, it will try
	// hiding any cells with priority > 0 in decreasing order (highest first).
	// For example:
	// - Priority 0 = the cell will never be hidden
	// - Priority 1 = highest priority, will be hidden last
	// - Priority 2 = lower priority than 1, will be hidden first
	Priority int
}

type DirectionalLayout struct {
	cells            []Cell
	flexCells        []layoutCell
	fixedStaticTotal int

	weightsTotal        int
	fixedDynamicIndexes []int // indexes into 'cells'
	priorityIndexes     []int // indexes into 'cells'
}

// Euclid's algorithm from wikipedia
func gcd(a, b int) int {
	for b != 0 {
		t := b
		b = a % b
		a = t
	}
	return a
}

func NewDirectionalLayout(cells []Cell) DirectionalLayout {
	var flexCells []layoutCell
	var fixedStaticTotal int
	var weightsTotal int
	var weightsGcd int
	var fixedDynamicIndexes []int
	var priorityIndex []int
	for i, c := range cells {
		// Negative widths are interpreted as weights. Positive widths are fixed.
		if c.Size < 0 {
			weightsTotal += -c.Size
			weightsGcd = gcd(weightsGcd, -c.Size)
			flexCells = append(flexCells, layoutCell{
				index:  i,
				weight: -c.Size,
			})
		} else if c.Size > 0 {
			fixedStaticTotal += c.Size
		} else if c.SizeFunc != nil {
			fixedDynamicIndexes = append(fixedDynamicIndexes, i)
		}
		if c.Priority != 0 {
			priorityIndex = append(priorityIndex, i)
		}
	}
	if len(priorityIndex) > 0 {
		slices.SortFunc(priorityIndex, func(a, b int) int {
			return -cmp.Compare(cells[a].Priority, cells[b].Priority)
		})
	}

	if weightsGcd != 0 {
		// Divide all weights by the gcd if needed, this is otherwise 1 if the
		// weights are already simplified
		weightsTotal /= weightsGcd
		for i := range flexCells {
			flexCells[i].weight /= weightsGcd
			flexCells[i].adjust = make([]int, weightsTotal)
		}
	}
	type flexColumnIndex struct {
		flexIndex int
		remainder float32
	}

	// After computing the integer widths for each column, we may be left with
	// remaining space to fill. The columns which had the largest fractional
	// component (i.e. would have rounded up) are given one extra width. These
	// adjustments can be precomputed since they repeat every (weightsTotal).
	for w := 1; w < weightsTotal; w++ {
		cellRemainders := make([]flexColumnIndex, len(flexCells))
		remainingUnits := w
		for i, fc := range flexCells {
			floorW := w * fc.weight / weightsTotal
			remainingUnits -= floorW
			cellRemainders[i] = flexColumnIndex{
				flexIndex: i,
				remainder: (float32(w) * float32(fc.weight) / float32(weightsTotal)) - float32(floorW),
			}
		}
		// stable sort columns descending by remainder
		slices.SortStableFunc(cellRemainders, func(a, b flexColumnIndex) int {
			return cmp.Compare(b.remainder, a.remainder)
		})
		// add 1 to the first remainingUnits columns with the highest remainders
		// for this value of w
		for i := range remainingUnits {
			flexCells[cellRemainders[i].flexIndex].adjust[w] = 1
		}
	}

	return DirectionalLayout{
		cells:               cells,
		flexCells:           flexCells,
		weightsTotal:        weightsTotal,
		fixedStaticTotal:    fixedStaticTotal,
		fixedDynamicIndexes: fixedDynamicIndexes,
		priorityIndexes:     priorityIndex,
	}
}

func (fc *DirectionalLayout) MinimumSizeHint() int {
	size := fc.fixedStaticTotal
	for _, idx := range fc.fixedDynamicIndexes {
		size += fc.cells[idx].SizeFunc()
	}
	return size
}

func (fc *DirectionalLayout) Resized(size int) []Cell {
	cells := slices.Clone(fc.cells)
	fixedTotal := fc.fixedStaticTotal
	for _, idx := range fc.fixedDynamicIndexes {
		sz := cells[idx].SizeFunc()
		cells[idx].Size = sz
		fixedTotal += sz
	}
	if fixedTotal > size {
		// start removing cells by priority until we get to <= size
		for _, idx := range fc.priorityIndexes {
			fixedTotal -= cells[idx].Size
			cells[idx].Size = 0
			if fixedTotal <= size {
				break
			}
		}
	}
	size = max(0, size-fixedTotal)

	if fc.weightsTotal == 0 {
		return cells
	}
	w := size % fc.weightsTotal
	for _, col := range fc.flexCells {
		cells[col.index].Size = size*col.weight/fc.weightsTotal + col.adjust[w]
	}
	return cells
}

type GridLayout struct {
	Rows   []Row
	layout DirectionalLayout
}

type RowCell struct {
	Title    string
	Size     int
	SizeFunc func() int
	Widget   core.Resizable
}

type Row struct {
	Height  int
	Columns []RowCell
	layout  DirectionalLayout
}

func NewGridLayout(rows []Row) *GridLayout {
	rowCells := make([]Cell, len(rows))
	for i, row := range rows {
		columnCells := make([]Cell, len(row.Columns))
		for j, col := range row.Columns {
			columnCells[j] = Cell{Title: col.Title, Size: col.Size, SizeFunc: col.SizeFunc}
		}
		rows[i].layout = NewDirectionalLayout(columnCells)
		rowCells[i] = Cell{Size: row.Height}
	}
	rowsLayout := NewDirectionalLayout(rowCells)
	return &GridLayout{
		layout: rowsLayout,
		Rows:   rows,
	}
}

func (g *GridLayout) Resize(width, height int) {
	sizedRows := g.layout.Resized(height)
	x, y := 0, 0
	for r, row := range sizedRows {
		sizedCols := g.Rows[r].layout.Resized(width)
		x = 0
		for c, col := range sizedCols {
			w := g.Rows[r].Columns[c].Widget
			if w != nil {
				w.SetBounds(uv.Rect(x, y, col.Size, row.Size))
			}
			x += col.Size
		}
		y += row.Size
	}
}
