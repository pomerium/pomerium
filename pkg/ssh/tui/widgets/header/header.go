package header

import (
	"charm.land/bubbles/v2/help"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"

	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Model struct {
	core.BaseModel
	AppName  string
	session  *models.Session
	width    int
	segments []HeaderSegment
	layout   layout.DirectionalLayout

	canvas *lipgloss.Canvas
}

type HeaderSegment struct {
	Label   string
	Content func(session *models.Session) string
	OnClick func(session *models.Session, globalPos uv.Position) tea.Cmd
	Styles  *style.ReactiveStyles[SegmentStyles]

	cellIndex int
}

func NewModel(config Config) *Model {
	leftAligned, rightAligned := config.LeftAlignedSegments, config.RightAlignedSegments
	cells := make([]layout.Cell, 0, len(leftAligned)+len(rightAligned)+1)
	hm := &Model{
		canvas: lipgloss.NewCanvas(),
		segments: append(append(leftAligned, HeaderSegment{
			Content: func(*models.Session) string { return "" },
		}), rightAligned...),
	}
	for i, hs := range leftAligned {
		leftAligned[i].cellIndex = len(cells)
		cells = append(cells, layout.Cell{
			Title: hs.Label,
			SizeFunc: func() int {
				return lipgloss.Width(hs.Content(hm.session)) + hs.Styles.Style().Base.GetHorizontalFrameSize()
			},
			Priority: i,
		})
	}
	cells = append(cells, layout.Cell{
		Size: -1, // Spacer
	})
	for i, hs := range rightAligned {
		rightAligned[i].cellIndex = len(cells)
		cells = append(cells, layout.Cell{
			Title: hs.Label,
			SizeFunc: func() int {
				return lipgloss.Width(hs.Content(hm.session)) + hs.Styles.Style().Base.GetHorizontalFrameSize()
			},
			Priority: len(rightAligned) - 1 - i,
		})
	}

	hm.layout = layout.NewDirectionalLayout(cells)
	return hm
}

func (s *Model) UpdateSession(session *models.Session) {
	s.session = session
	s.rebuildCanvas()
}

func (s *Model) OnResized(width, _ int) {
	s.width = width
	s.rebuildCanvas()
}

func (s *Model) rebuildCanvas() {
	cells := s.layout.Resized(s.width)
	x := 0
	layers := make([]*lipgloss.Layer, 0, len(cells))
	for i, cell := range cells {
		segment := s.segments[i]
		content := segment.Content(s.session)
		var baseStyle lipgloss.Style
		if segment.Styles != nil {
			baseStyle = segment.Styles.Style().Base
		}
		layer := lipgloss.NewLayer(baseStyle.Render(content)).ID(cell.Title).Width(cell.Size).X(x).Y(0)
		x += layer.GetWidth()
		layers = append(layers, layer)
	}
	canvas := lipgloss.NewCanvas(layers...)
	s.canvas = canvas
}

func (s *Model) SizeHint() (int, int) {
	return s.layout.MinimumSizeHint(), 1
}

func (s *Model) Blur() tea.Cmd       { return nil }
func (s *Model) Focus() tea.Cmd      { return nil }
func (s *Model) Focused() bool       { return false }
func (s *Model) KeyMap() help.KeyMap { return nil }
func (s *Model) View() uv.Drawable {
	return s.canvas
}

func (s *Model) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.MouseClickMsg:
		global := uv.Pos(msg.X, msg.Y)
		local := s.Parent().TranslateGlobalToLocalPos(global)
		if s.canvas != nil {
			id := s.canvas.Hit(local.X, local.Y)
			for _, segment := range s.segments {
				if segment.Label == id {
					if segment.OnClick != nil {
						return segment.OnClick(s.session, global)
					}
					break
				}
			}
		}
	}
	return nil
}
