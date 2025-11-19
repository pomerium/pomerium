package tui

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
	"github.com/charmbracelet/x/ansi"

	"github.com/pomerium/pomerium/pkg/slices"
)

type LogEntry struct {
	Index     int
	Message   string
	Timestamp string
	Count     int
}

type LogViewerKeyMap struct {
	LineUp     key.Binding
	LineDown   key.Binding
	PageUp     key.Binding
	PageDown   key.Binding
	GotoTop    key.Binding
	GotoBottom key.Binding
}

// ShortHelp implements the KeyMap interface.
func (km LogViewerKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{km.LineUp, km.LineDown}
}

// FullHelp implements the KeyMap interface.
func (km LogViewerKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{km.LineUp, km.LineDown, km.GotoTop, km.GotoBottom},
		{km.PageUp, km.PageDown},
	}
}

type LogViewerStyles struct {
	Style                lipgloss.Style
	Focused              lipgloss.Style
	BorderTitleLeft      string
	BorderTitleRight     string
	ShowTimestamp        bool
	Timestamp            lipgloss.Style
	HideScrollbarButtons bool
	AlwaysShowScrollbar  bool
}

type LogViewer struct {
	styles             LogViewerStyles
	tail               *ring.Ring // the logical "end" of the ring (the most recent log)
	visibleHead        *ring.Ring // the first visible entry
	visibleTail        *ring.Ring // the last visible entry
	width, height      int
	len, cap           int
	focused            bool
	keyMap             LogViewerKeyMap
	scrollbar          Scrollbar
	scrollbarGrabStart int
}

func NewLogViewerModel(bufferSize int, styles LogViewerStyles) *LogViewer {
	m := &LogViewer{
		styles: styles,
		tail:   ring.New(bufferSize),
		len:    0,
		cap:    bufferSize,
	}
	m.scrollbar.SetStyles(ScrollbarStyles{
		Arrows:    !m.styles.HideScrollbarButtons,
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

func (m *LogViewer) KeyMap() help.KeyMap {
	return LogViewerKeyMap{
		LineUp: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		LineDown: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("b", "pgup"),
			key.WithHelp("b/pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("f", "pgdown", "space"),
			key.WithHelp("f/pgdn", "page down"),
		),
		GotoTop: key.NewBinding(
			key.WithKeys("home", "g"),
			key.WithHelp("g/home", "go to start"),
		),
		GotoBottom: key.NewBinding(
			key.WithKeys("end", "G"),
			key.WithHelp("G/end", "go to end"),
		),
	}
}

func (m *LogViewer) Push(msg string) {
	var timestamp string
	if m.styles.ShowTimestamp {
		timestamp = m.styles.Timestamp.Render(fmt.Sprintf("[%sZ]", time.Now().UTC().Format(time.TimeOnly)))
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

func (m *LogViewer) scrollUpOne() bool {
	prev := m.visibleHead.Prev()
	if prev == m.tail || prev.Value.(*LogEntry).Count == 0 {
		return false
	}
	m.visibleHead = m.visibleHead.Prev()
	m.visibleTail = m.visibleTail.Prev()
	return true
}

func (m *LogViewer) scrollDownOne() bool {
	if m.visibleTail == m.tail {
		return false
	}
	m.visibleHead = m.visibleHead.Next()
	m.visibleTail = m.visibleTail.Next()
	return true
}

func (m *LogViewer) scrollUpN(n int) {
	for range n {
		if !m.scrollUpOne() {
			return
		}
	}
}

func (m *LogViewer) scrollDownN(n int) {
	for range n {
		if !m.scrollDownOne() {
			return
		}
	}
}

func (m *LogViewer) scrollToTop() {
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

func (m *LogViewer) scrollToBottom() {
	m.visibleTail = m.tail
	m.visibleHead = m.visibleTail.Move(1 - m.height)
}

func (m *LogViewer) SetSize(maxWidth, maxHeight int) {
	maxWidth = max(0, maxWidth-m.styles.Style.GetHorizontalFrameSize())
	maxHeight = max(0, maxHeight-m.styles.Style.GetVerticalFrameSize())
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

func (m *LogViewer) Update(msg tea.Msg) (*LogViewer, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if !m.focused {
			break
		}
		switch msg.String() {
		case "up":
			m.scrollUpOne()
		case "down":
			m.scrollDownOne()
		case "pgup":
			m.scrollUpN(m.height)
		case "pgdown":
			m.scrollDownN(m.height)
		case "g":
			m.scrollToTop()
		case "G":
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
		if msg.X == m.width { // scrollbar
			if msg.Button == tea.MouseLeft && m.shouldDisplayScrollbar() {
				switch m.scrollbar.HitTest(msg.Y - m.styles.Style.GetBorderTopSize()) {
				case HitNone:
				case HitUpButton:
					m.scrollUpOne()
				case HitTrackAboveSlider:
					m.scrollUpN(m.scrollbar.VisualSliderPageSize())
				case HitSlider:
					m.scrollbarGrabStart = msg.Y
				case HitTrackBelowSlider:
					m.scrollDownN(m.scrollbar.VisualSliderPageSize())
				case HitDownButton:
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
	}
	return m, nil
}

var textBlue = lipgloss.NewStyle().Foreground(ansi.Blue)

func (m *LogViewer) View() string {
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

	style := m.styles.Style
	if m.focused {
		style = style.Inherit(m.styles.Focused)
	}

	// check if we need to render the scrollbar
	if m.shouldDisplayScrollbar() {
		m.scrollbar.SetHeight(m.height)
		m.scrollbar.SetValue(m.scrollIndex())
		m.scrollbar.SetMax(max(0, m.len-m.height))
		rows := m.scrollbar.Rows()
		for i, r := range rows {
			lines[i][len(lines[i])-1] = r
		}
	}
	lineStrings := make([]string, len(lines))
	for i, l := range lines {
		lineStrings[i] = string(l)
	}
	content := style.UnsetBorderTop().Render(lipgloss.JoinVertical(lipgloss.Left, lineStrings...))
	topBorder := style.Width(lipgloss.Width(content)).Render()
	topBorder = topBorder[:strings.IndexRune(topBorder, '\n')]

	if bs := m.styles.Style.GetBorderStyle(); bs.Top != "" &&
		(m.styles.BorderTitleLeft != "" || m.styles.BorderTitleRight != "") {
		topRune := []rune(bs.Top)[0]
		borderRunes := []rune(topBorder)
		left := stdslices.Index(borderRunes, topRune)
		right := slices.LastIndex(borderRunes, topRune)
		if m.styles.BorderTitleLeft != "" {
			text := []rune(fmt.Sprintf("╴%s╶", m.styles.BorderTitleLeft))
			if left+len(text) < right {
				left += copy(borderRunes[left:], text)
			}
		}
		if m.styles.BorderTitleRight != "" {
			text := []rune(fmt.Sprintf("╴%s╶", m.styles.BorderTitleRight))
			if right-len(text) > left {
				copy(borderRunes[right-len(text)+1:], text)
			}
		}
		topBorder = string(borderRunes)
	}
	return lipgloss.JoinVertical(lipgloss.Left, topBorder, content)
}

func (m *LogViewer) shouldDisplayScrollbar() bool {
	return m.len > m.height || m.styles.AlwaysShowScrollbar
}

func (m *LogViewer) scrollIndex() int {
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

func (m *LogViewer) ringDistance(from *ring.Ring, to *ring.Ring) int {
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

func (m *LogViewer) SetFocused(focused bool) *LogViewer {
	m.focused = focused
	return m
}

func (m *LogViewer) Focused() bool {
	return m.focused
}

func (m *LogViewer) Focus() {
	m.focused = true
}

func (m *LogViewer) Blur() {
	m.focused = false
}
