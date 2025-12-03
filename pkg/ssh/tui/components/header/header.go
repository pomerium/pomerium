package header

import (
	"charm.land/bubbles/v2/help"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/model"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
)

type Widget = core.Widget[*Model]

type Model struct {
	AppName  string
	session  *model.Session
	width    int
	segments []HeaderSegment
	layout   layout.DirectionalLayout

	canvas *lipgloss.Canvas
}

type HeaderSegment struct {
	Label     string
	Content   func(*model.Session) string
	OnClick   func(xy uv.Position) tea.Cmd
	Style     lipgloss.Style
	cellIndex int
}

func NewHeaderModel(leftAligned []HeaderSegment, rightAligned []HeaderSegment) *Model {
	cells := make([]layout.Cell, 0, len(leftAligned)+len(rightAligned)+1)
	hm := &Model{
		canvas: lipgloss.NewCanvas(),
		segments: append(append(leftAligned, HeaderSegment{
			Content: func(*model.Session) string { return "" },
		}), rightAligned...),
	}
	for i, hs := range leftAligned {
		leftAligned[i].cellIndex = len(cells)
		cells = append(cells, layout.Cell{
			Title:    hs.Label,
			SizeFunc: func() int { return lipgloss.Width(hs.Content(hm.session)) + hs.Style.GetHorizontalFrameSize() },
			Style:    func(string) lipgloss.Style { return hs.Style },
			Priority: i,
		})
	}
	cells = append(cells, layout.Cell{
		Size:  -1, // Spacer
		Style: func(string) lipgloss.Style { return lipgloss.Style{} },
	})
	for i, hs := range rightAligned {
		rightAligned[i].cellIndex = len(cells)
		cells = append(cells, layout.Cell{
			Title:    hs.Label,
			SizeFunc: func() int { return lipgloss.Width(hs.Content(hm.session)) + hs.Style.GetHorizontalFrameSize() },
			Style:    func(string) lipgloss.Style { return hs.Style },
			Priority: len(rightAligned) - 1 - i,
		})
	}

	hm.layout = layout.NewDirectionalLayout(cells)
	return hm
}

func (s *Model) UpdateSession(session *model.Session) {
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
		content := s.segments[i].Content(s.session)
		layer := lipgloss.NewLayer(cell.Style(content).Render(content)).ID(cell.Title).Width(cell.Size).X(x).Y(0)
		x += layer.GetWidth()
		layers = append(layers, layer)
	}
	canvas := lipgloss.NewCanvas(layers...)
	s.canvas = canvas
}

func (s *Model) Blur()               {}
func (s *Model) Focus()              {}
func (s *Model) Focused() bool       { return false }
func (s *Model) KeyMap() help.KeyMap { return nil }
func (s *Model) View() uv.Drawable {
	return s.canvas
}

func (s *Model) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.MouseClickMsg:
		if s.canvas != nil {
			id := s.canvas.Hit(msg.X, msg.Y)
			for _, segment := range s.segments {
				if segment.Label == id {
					if segment.OnClick != nil {
						return segment.OnClick(uv.Pos(msg.X, msg.Y))
					}
					break
				}
			}
		}
	}
	return nil
}
