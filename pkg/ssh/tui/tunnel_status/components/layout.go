package components

import (
	"cmp"
	"iter"
	"maps"
	"slices"
	"strings"

	"charm.land/bubbles/v2/key"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
)

type ComponentBuilder struct {
	lc *LayoutComponent
}

func (b ComponentBuilder) Mnemonic(mnemonic string) ComponentBuilder {
	b.lc.mnemonic = mnemonic
	return b
}

func (b ComponentBuilder) StartsHidden(startsHidden bool) ComponentBuilder {
	b.lc.startsHidden = startsHidden
	return b
}

// RowHint sets a row number weight to use when building the layout. Components
// are grouped into rows with other components that have the same row hint,
// then all rows are sorted by value from smallest to largest. The hint number
// does not necessarily correspond with the computed row (similar to z-index)
func (b ComponentBuilder) RowHint(hint int) ComponentBuilder {
	b.lc.rowHint = hint
	return b
}

// ColumnHint sets a column number weight to use when building the layout.
// Within a single row (see [ComponentBuilder.RowHint]), components are
// sorted by their column hint from smallest to largest. Like with the row
// hint, the column hint number does not necessarily correspond with the
// computed column within the row.
func (b ComponentBuilder) ColumnHint(hint int) ComponentBuilder {
	b.lc.columnHint = hint
	return b
}

// Width sets a fixed width or horizontal stretch factor to use for this
// component within its row.
// Positive values are fixed. Negative values are stretch factors.
func (b ComponentBuilder) Width(width int) ComponentBuilder {
	b.lc.width = width
	return b
}

// Height sets a fixed height or vertical stretch factor for this component.
// When computing row heights, the largest value among all components in that
// row is used as the entire row's stretch factor.
// Positive values are fixed. Negative values are stretch factors.
func (b ComponentBuilder) Height(height int) ComponentBuilder {
	b.lc.height = height
	return b
}

func (b ComponentBuilder) WidgetID(id string) ComponentBuilder {
	b.lc.widgetID = id
	return b
}

func (b ComponentBuilder) Type(componentType string) *LayoutComponent {
	b.lc.componentType = componentType
	return b.lc
}

func New() ComponentBuilder {
	return ComponentBuilder{
		lc: &LayoutComponent{
			startsHidden: false,
			width:        -1, // default to equally spaced
			height:       -1, //
		},
	}
}

type LayoutComponent struct {
	componentType       string
	widgetID            string
	mnemonic            string
	startsHidden        bool
	rowHint, columnHint int
	width, height       int
}

func (bc *LayoutComponent) Type() string { return bc.componentType }
func (bc *LayoutComponent) ID() string {
	if bc.widgetID != "" {
		return bc.widgetID
	}
	return bc.componentType
}
func (bc *LayoutComponent) StartsHidden() bool { return bc.startsHidden }
func (bc *LayoutComponent) Mnemonic() string   { return bc.mnemonic }
func (bc *LayoutComponent) RowHint() int       { return bc.rowHint }
func (bc *LayoutComponent) ColumnHint() int    { return bc.columnHint }
func (bc *LayoutComponent) LayoutWidth() int   { return bc.width }
func (bc *LayoutComponent) LayoutHeight() int  { return bc.height }

var _ Component = (*LayoutComponent)(nil)

type GroupComponentWidget struct {
	Component
	core.Widget
	computedRow, computedColumn int
}

func (bc *GroupComponentWidget) Row() int    { return bc.computedRow }
func (bc *GroupComponentWidget) Column() int { return bc.computedColumn }

type Group struct {
	byRow           [][]*GroupComponentWidget
	byID            map[string]*GroupComponentWidget
	byMnemonic      map[string]*GroupComponentWidget
	mnemonicBinding key.Binding
}

func (cs *Group) RowMajorOrder() iter.Seq[ComponentWidget] {
	return func(yield func(ComponentWidget) bool) {
		for _, row := range cs.byRow {
			for _, c := range row {
				if !yield(c) {
					return
				}
			}
		}
	}
}

func (cs *Group) LookupID(id string) (ComponentWidget, bool) {
	c, ok := cs.byID[id]
	return c, ok
}

func (cs *Group) LookupMnemonic(mnemonic string) (ComponentWidget, bool) {
	c, ok := cs.byMnemonic[mnemonic]
	return c, ok
}

func (cs *Group) MnemonicBinding() key.Binding {
	return cs.mnemonicBinding
}

func (cs *Group) Size() int {
	return len(cs.byID) // NewLayout enforces unique IDs for each component
}

func (cs *Group) ToLayoutRows() []layout.Row {
	visibleRows := []layout.Row{}
	for _, row := range cs.byRow {
		var lr layout.Row
		for _, comp := range row {
			if comp.Hidden() {
				continue
			}
			if lr.Height > 0 && comp.LayoutHeight() > 0 {
				// if all cells are fixed, use the largest height
				lr.Height = max(lr.Height, comp.LayoutHeight())
			} else {
				// any negative values take precedence
				lr.Height = min(lr.Height, comp.LayoutHeight())
			}
			lr.Columns = append(lr.Columns, layout.RowCell{
				Title:  comp.ID(),
				Size:   comp.LayoutWidth(),
				Widget: comp,
			})
		}
		if len(lr.Columns) > 0 && lr.Height != 0 {
			visibleRows = append(visibleRows, lr)
		}
	}
	return visibleRows
}

func NewGroup(factories ComponentFactoryRegistry, components ...Component) *Group {
	if len(components) == 0 {
		return &Group{}
	}
	widgets := make([]*GroupComponentWidget, len(components))
	for i, component := range components {
		widgets[i] = &GroupComponentWidget{
			Component: component,
			Widget:    factories.NewComponentWidget(component),
		}
	}
	// sort components in row-major order
	slices.SortStableFunc(components, func(a, b Component) int {
		return cmp.Or(cmp.Compare(a.RowHint(), b.RowHint()), cmp.Compare(a.ColumnHint(), b.ColumnHint()))
	})

	byRow := [][]*GroupComponentWidget{}
	byID := make(map[string]*GroupComponentWidget, len(widgets))
	byMnemonic := make(map[string]*GroupComponentWidget, len(widgets))
	current := widgets[0].RowHint()
	start := 0
	for i, c := range widgets {
		if c.RowHint() != current {
			byRow = append(byRow, widgets[start:i])
			current = c.RowHint()
			start = i
		}
		c.computedRow = len(byRow)
		c.computedColumn = i - start
		id := c.ID()
		if _, ok := byID[id]; ok {
			panic("bug: duplicate component id: " + id)
		}
		mnemonic := c.Mnemonic()
		if _, ok := byMnemonic[mnemonic]; ok {
			panic("bug: duplicate component mnemonic: " + id)
		}
		byID[id] = c
		byMnemonic[mnemonic] = c
	}
	byRow = append(byRow, widgets[start:])

	allKeys := slices.Sorted(maps.Keys(byMnemonic))

	return &Group{
		byRow:      byRow,
		byID:       byID,
		byMnemonic: byMnemonic,
		mnemonicBinding: key.NewBinding(
			key.WithKeys(allKeys...),
			key.WithHelp(strings.Join(allKeys, "/"), "toggle panel visibility"),
		),
	}
}
