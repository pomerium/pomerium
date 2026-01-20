package logviewer

import (
	"container/ring"
	"fmt"
	"math"
	stdslices "slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"

	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/scrollbar"
)

type LogEntry struct {
	Index     int
	Message   string
	Timestamp string
	Count     int
}

type KeyMap struct {
	LineUp     key.Binding
	LineDown   key.Binding
	PageUp     key.Binding
	PageDown   key.Binding
	GotoTop    key.Binding
	GotoBottom key.Binding
}

// ShortHelp implements the KeyMap interface.
func (km KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{km.LineUp, km.LineDown}
}

// FullHelp implements the KeyMap interface.
func (km KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{km.LineUp, km.LineDown, km.GotoTop, km.GotoBottom},
		{km.PageUp, km.PageDown},
	}
}

type Model struct {
	core.BaseModel
	config             Config
	tail               *ring.Ring // the logical "end" of the ring (the most recent log)
	visibleHead        *ring.Ring // the first visible entry
	visibleTail        *ring.Ring // the last visible entry
	width, height      int
	len, cap           int
	focused            bool
	scrollbar          scrollbar.Scrollbar
	scrollbarGrabStart int
}

func NewModel(config Config) *Model {
	core.ApplyKeyMapDefaults(&config.KeyMap, DefaultKeyMap)
	m := &Model{
		config: config,
		tail:   ring.New(config.BufferSize),
		len:    0,
		cap:    config.BufferSize,
	}
	m.scrollbar.SetStyles(scrollbar.Styles{
		Arrows:    !m.config.HideScrollbarButtons,
		UpArrow:   '⌃',
		DownArrow: '⌄',
	})
	m.tail.Value = &LogEntry{Index: 0}
	index := 1
	for r := m.tail.Next(); r != m.tail; r = r.Next() {
		r.Value = &LogEntry{Index: index}
		index++
	}
	m.visibleHead = m.tail.Next()
	m.visibleTail = m.tail
	return m
}

func (m *Model) KeyMap() help.KeyMap {
	return m.config.KeyMap
}

func (m *Model) Push(msg string) {
	var timestamp string
	if m.config.ShowTimestamp {
		timestamp = m.config.Styles.Style().Timestamp.Render(fmt.Sprintf("[%sZ]", time.Now().UTC().Format(time.TimeOnly)))
	}
	if last := m.tail.Value.(*LogEntry); last != nil && last.Timestamp == timestamp && last.Message == msg {
		last.Count++
		return
	}
	m.len = min(m.len+1, m.cap)
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
	entry := pendingTail.Value.(*LogEntry)
	entry.Count = 1
	entry.Message = msg
	entry.Timestamp = timestamp
	m.tail = pendingTail
}

func (m *Model) scrollUpOne() bool {
	prev := m.visibleHead.Prev()
	if prev == m.tail || prev.Value.(*LogEntry).Count == 0 {
		return false
	}
	m.visibleHead = m.visibleHead.Prev()
	m.visibleTail = m.visibleTail.Prev()
	return true
}

func (m *Model) scrollDownOne() bool {
	if m.visibleTail == m.tail {
		return false
	}
	m.visibleHead = m.visibleHead.Next()
	m.visibleTail = m.visibleTail.Next()
	return true
}

func (m *Model) scrollUpN(n int) {
	for range n {
		if !m.scrollUpOne() {
			return
		}
	}
}

func (m *Model) scrollDownN(n int) {
	for range n {
		if !m.scrollDownOne() {
			return
		}
	}
}

func (m *Model) scrollToTop() {
	// fast path: all entries have a value
	if m.tail.Next().Value.(*LogEntry).Count != 0 {
		m.visibleHead = m.tail.Next()
		m.visibleTail = m.visibleHead.Move(m.height - 1)
		return
	}
	// walk backwards from visibleHead until we reach a missing entry
	for {
		prev := m.visibleHead.Prev()
		if prev.Value.(*LogEntry).Count == 0 {
			break
		}
		m.visibleHead = prev
		// move visibleTail along with it
		m.visibleTail = m.visibleTail.Prev()
	}
}

func (m *Model) scrollToBottom() {
	m.visibleTail = m.tail
	m.visibleHead = m.visibleTail.Move(1 - m.height)
}

func (m *Model) OnResized(maxWidth, maxHeight int) {
	maxWidth = max(0, maxWidth-m.config.Styles.Style().Border.GetHorizontalFrameSize())
	maxHeight = max(0, maxHeight-m.config.Styles.Style().Border.GetVerticalFrameSize())
	shrinkBy := m.height - maxHeight
	for range int(math.Abs(float64(shrinkBy))) {
		if shrinkBy < 0 {
			// grow
			m.visibleHead = m.visibleHead.Prev()
		} else {
			// shrink
			m.visibleHead = m.visibleHead.Next()
		}
	}
	m.width = maxWidth
	m.height = maxHeight
	m.scrollbarGrabStart = -1
}

func (m *Model) SizeHint() (int, int) {
	return m.config.Styles.Style().Border.GetFrameSize()
}

func (m *Model) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if !m.focused {
			break
		}
		switch {
		case key.Matches(msg, m.config.KeyMap.LineUp):
			m.scrollUpOne()
		case key.Matches(msg, m.config.KeyMap.LineDown):
			m.scrollDownOne()
		case key.Matches(msg, m.config.KeyMap.PageUp):
			m.scrollUpN(m.height)
		case key.Matches(msg, m.config.KeyMap.PageDown):
			m.scrollDownN(m.height)
		case key.Matches(msg, m.config.KeyMap.GotoTop):
			m.scrollToTop()
		case key.Matches(msg, m.config.KeyMap.GotoBottom):
			m.scrollToBottom()
		}
	case tea.MouseWheelMsg:
		if !m.focused {
			break
		}
		switch msg.Button {
		case tea.MouseWheelUp:
			n := 3
			if (msg.Mod & tea.ModCtrl) != 0 {
				n = m.height
			}
			m.scrollUpN(n)
		case tea.MouseWheelDown:
			n := 3
			if (msg.Mod & tea.ModCtrl) != 0 {
				n = m.height
			}
			for range n {
				m.scrollDownOne()
			}
		}
	case tea.MouseClickMsg:
		m.scrollbarGrabStart = -1
		if !m.focused {
			break
		}
		global := uv.Pos(msg.X, msg.Y)
		local, inBounds := m.Parent().TranslateGlobalToLocalPos(global)
		if !inBounds {
			return nil
		}

		if local.X == m.width { // scrollbar
			if msg.Button == tea.MouseLeft && m.shouldDisplayScrollbar() {
				switch m.scrollbar.HitTest(local.Y - m.config.Styles.Style().Border.GetBorderTopSize()) {
				case scrollbar.HitNone:
				case scrollbar.HitUpButton:
					m.scrollUpOne()
				case scrollbar.HitTrackAboveSlider:
					m.scrollUpN(m.scrollbar.VisualSliderPageSize())
				case scrollbar.HitSlider:
					m.scrollbarGrabStart = local.Y
				case scrollbar.HitTrackBelowSlider:
					m.scrollDownN(m.scrollbar.VisualSliderPageSize())
				case scrollbar.HitDownButton:
					m.scrollDownOne()
				}
			}
		}
	case tea.MouseReleaseMsg:
		m.scrollbarGrabStart = -1
	case tea.MouseMotionMsg:
		if m.scrollbarGrabStart != -1 {
			if msg.Y < m.scrollbarGrabStart {
				m.scrollbarGrabStart--
				m.scrollUpN(m.scrollbar.VisualPageSize())
			} else if msg.Y > m.scrollbarGrabStart {
				m.scrollbarGrabStart++
				m.scrollDownN(m.scrollbar.VisualPageSize())
			}
		}
	case AddLogsMsg:
		for _, l := range msg.Logs {
			m.Push(l)
		}
	}
	return nil
}

var textBlue = lipgloss.NewStyle().Foreground(ansi.Blue)

func (m *Model) View() uv.Drawable {
	node := m.visibleHead
	lines := make([][]rune, 0, m.height)
	for range m.height {
		entry := node.Value.(*LogEntry)
		var value string
		if entry.Count == 1 {
			value = strings.Join([]string{entry.Timestamp, entry.Message}, " ")
		} else if entry.Count > 1 {
			value = strings.Join([]string{entry.Timestamp, textBlue.Render(fmt.Sprintf("(x%d)", entry.Count)), entry.Message}, " ")
		}
		line := []rune(ansi.Truncate(value, m.width-1, "…"))
		// pad the line to match the actual rendered width
		padding := max(0, m.width-lipgloss.Width(string(line)))
		line = append(line, stdslices.Repeat([]rune{' '}, padding)...)
		lines = append(lines, line)
		if node == m.visibleTail {
			break
		}
		node = node.Next()
	}

	// check if we need to render the scrollbar
	if m.shouldDisplayScrollbar() {
		m.scrollbar.SetHeight(m.height)
		m.scrollbar.SetValue(m.scrollIndex())
		m.scrollbar.SetMaxValue(max(0, m.len-m.height))
		rows := m.scrollbar.Rows()
		for i, r := range rows {
			lines[i][len(lines[i])-1] = r
		}
	}

	border := m.config.Styles.Style().Border
	if m.focused {
		border = m.config.Styles.Style().BorderFocused
	}

	var sb strings.Builder
	sb.Grow(m.width * m.height)
	for i, line := range lines {
		sb.WriteString(string(line))
		if i < len(lines)-1 {
			sb.WriteByte('\n')
		}
	}
	return uv.NewStyledString(
		style.RenderBorderTitles(
			border.Render(sb.String()),
			border.GetBorderStyle(),
			m.config.BorderTitleLeft,
			m.config.BorderTitleRight))
}

func (m *Model) shouldDisplayScrollbar() bool {
	return m.len > m.height || m.config.AlwaysShowScrollbar
}

func (m *Model) scrollIndex() int {
	// fast path: all entries have a value
	if m.tail.Next().Value.(*LogEntry).Count > 0 {
		return m.ringDistance(m.tail.Next(), m.visibleHead)
	}
	// walk backwards from visibleHead until we reach a missing entry
	r := m.visibleHead
	for r.Prev().Value.(*LogEntry).Count > 0 {
		r = r.Prev()
	}
	return m.ringDistance(r, m.visibleHead)
}

func (m *Model) ringDistance(from *ring.Ring, to *ring.Ring) int {
	a, b := from.Value.(*LogEntry).Index, to.Value.(*LogEntry).Index
	if a == b {
		return 0
	}
	// consider b to be "after" a
	b -= a
	if b < 0 {
		b += m.cap
	}
	return b
}

func (m *Model) SetFocused(focused bool) *Model {
	m.focused = focused
	return m
}

func (m *Model) Focused() bool {
	return m.focused
}

func (m *Model) Focus() tea.Cmd {
	m.focused = true
	return nil
}

func (m *Model) Blur() tea.Cmd {
	m.focused = false
	return nil
}

type AddLogsMsg struct {
	Logs []string
}

func AddLogs(logs ...string) tea.Cmd {
	return func() tea.Msg {
		return AddLogsMsg{Logs: logs}
	}
}
