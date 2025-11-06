package tui

import (
	"container/ring"
	"math"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type LogViewerModel struct {
	buffer      *ring.Ring
	tail        *ring.Ring // the logical "end" of the ring (the most recent log)
	visibleHead *ring.Ring // the first visible entry
	visibleTail *ring.Ring // the last visible entry
	style       lipgloss.Style
	focused     bool
}

func NewLogViewerModel(style lipgloss.Style, bufferSize int) *LogViewerModel {
	m := &LogViewerModel{
		buffer: ring.New(bufferSize),
		style:  style,
	}
	m.tail = m.buffer
	m.visibleHead = m.tail.Next()
	m.visibleTail = m.tail
	return m
}

func (m *LogViewerModel) Push(line string) {
	pendingTail := m.tail.Next()
	if m.tail == m.visibleTail {
		// the view is scrolled to the bottom of the list
		m.visibleHead = m.visibleHead.Next()
		m.visibleTail = pendingTail
	} else if pendingTail == m.visibleHead {
		// the first visible log is the oldest and it is about to be overwritten, so
		// move the visible head to the next oldest log
		m.visibleHead = m.visibleHead.Next()
		m.visibleTail = m.visibleTail.Next()
	}
	pendingTail.Value = line
	m.tail = pendingTail
}

func (m *LogViewerModel) scrollUpOne() {
	prev := m.visibleHead.Prev()
	if prev == m.tail || prev.Value == nil {
		return
	}
	m.visibleHead = m.visibleHead.Prev()
	m.visibleTail = m.visibleTail.Prev()
}

func (m *LogViewerModel) scrollDownOne() {
	if m.visibleTail == m.tail {
		return
	}
	m.visibleHead = m.visibleHead.Next()
	m.visibleTail = m.visibleTail.Next()
}

func (m *LogViewerModel) scrollToTop() {
	height := m.style.GetHeight()
	// fast path: all entries have a value
	if m.tail.Next().Value != nil {
		m.visibleHead = m.tail.Next()
		m.visibleTail = m.visibleHead.Move(height - 1)
		return
	}
	// walk backwards from visibleHead until we reach a missing entry
	for {
		prev := m.visibleHead.Prev()
		if prev.Value == nil {
			break
		}
		m.visibleHead = prev
		// move visibleTail along with it
		m.visibleTail = m.visibleTail.Prev()
	}
}

func (m *LogViewerModel) scrollToBottom() {
	height := m.style.GetHeight()
	m.visibleTail = m.tail
	m.visibleHead = m.visibleTail.Move(1 - height)
}

func (m *LogViewerModel) WithDimensions(maxWidth, maxHeight int) *LogViewerModel {
	shrinkBy := m.style.GetHeight() - max(0, maxHeight-m.style.GetVerticalFrameSize())
	for range int(math.Abs(float64(shrinkBy))) {
		if shrinkBy < 0 {
			// grow
			m.visibleHead = m.visibleHead.Prev()
		} else {
			// shrink
			m.visibleHead = m.visibleHead.Next()
		}
	}
	m.style = m.style.
		Width(max(0, maxWidth-m.style.GetHorizontalFrameSize())).
		Height(max(0, maxHeight-m.style.GetVerticalFrameSize()))
	return m
}

func (m *LogViewerModel) Update(msg tea.Msg) (*LogViewerModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if !m.focused {
			break
		}
		switch msg.String() {
		case "up":
			// shift up
			m.scrollUpOne()
		case "down":
			// shift down
			m.scrollDownOne()
		case "pgup":
			for range 10 {
				m.scrollUpOne()
			}
		case "pgdown":
			for range 10 {
				m.scrollDownOne()
			}
		case "g":
			m.scrollToTop()
		case "G":
			m.scrollToBottom()
		}
	}
	return m, nil
}

func (m *LogViewerModel) View() string {
	node := m.visibleHead
	width, height := m.style.GetWidth(), m.style.GetHeight()
	lines := make([]string, 0, height)
	for range height {
		value := node.Value
		switch value := value.(type) {
		case string:
			line := ansi.Truncate(value, width, "…")
			lines = append(lines, line)
		case nil:
		}
		if node == m.visibleTail {
			break
		}
		node = node.Next()
	}

	return m.style.Render(lipgloss.JoinVertical(lipgloss.Left, lines...))
}

func (m *LogViewerModel) Focused(focused bool) *LogViewerModel {
	m.focused = focused
	return m
}
