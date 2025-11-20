package tui

import (
	"cmp"
	"slices"

	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/tui/table"
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
	Title string
	Size  int
	Style func(string) lipgloss.Style // for table.Column passthrough
}

type DirectionalLayout struct {
	cells        []Cell
	flexCells    []layoutCell
	fixedTotal   int
	weightsTotal int
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
	var fixedTotal int
	var weightsTotal int
	var weightsGcd int
	for i, c := range cells {
		// Negative widths are interpreted as weights. Positive widths are fixed.
		if c.Size < 0 {
			weightsTotal += -c.Size
			weightsGcd = gcd(weightsGcd, -c.Size)
			flexCells = append(flexCells, layoutCell{
				index:  i,
				weight: -c.Size,
			})
		} else {
			fixedTotal += c.Size
		}
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
		cells:        cells,
		flexCells:    flexCells,
		weightsTotal: weightsTotal,
		fixedTotal:   fixedTotal,
	}
}

type Cells []Cell

func (c Cells) AsColumns() []table.Column {
	cols := make([]table.Column, len(c))
	for i, cell := range c {
		cols[i] = table.Column{Title: cell.Title, Width: cell.Size, CellStyle: cell.Style}
	}
	return cols
}

func (fc *DirectionalLayout) Resized(size int) Cells {
	size = max(0, size-fc.fixedTotal)
	cells := slices.Clone(fc.cells)
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
	Title string
	Size  int
	Rect  *uv.Rectangle
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
			columnCells[j] = Cell{Title: col.Title, Size: col.Size}
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
			*g.Rows[r].Columns[c].Rect = uv.Rect(x, y, col.Size, row.Size)
			x += col.Size
		}
		y += row.Size
	}
	if (x != width || y != height) && g.layout.weightsTotal > 0 {
		panic("bug")
	}
}
