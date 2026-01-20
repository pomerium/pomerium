// MIT License
//
// Copyright (c) 2020-2025 Charmbracelet, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// Package table is adapted from https://github.com/charmbracelet/bubbles/blob/v2.0.0-beta.1/table/table.go
package table

import (
	"slices"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"

	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/messages"
)

type TableModel[T models.Item[K], K comparable] interface {
	models.ItemModel[T, K]
	BuildRow(item T) []string
}

type Mode int

const (
	Normal Mode = iota
	Edit
)

type editState struct {
	editInput   textinput.Model
	interceptor *messages.ModalInterceptor
	row, col    int
	onSubmit    func(string)
	lastError   error
}

// Model defines a state for the table widget.
type Model[T models.Item[K], K comparable] struct {
	core.BaseModel
	itemModel TableModel[T, K]

	keyMap     KeyMap
	editKeyMap EditKeyMap

	cols      []Column
	rows      []Row
	cursor    int
	focus     bool
	config    Config[T, K]
	mode      Mode
	editState editState

	viewport viewport.Model
	start    int
	end      int
}

func NewModel[T models.Item[K], K comparable](cfg Config[T, K], itemModel TableModel[T, K]) *Model[T, K] {
	core.ApplyKeyMapDefaults(&cfg.KeyMap, DefaultKeyMap)
	core.ApplyKeyMapDefaults(&cfg.EditKeyMap, DefaultEditKeyMap)
	m := &Model[T, K]{
		config:     cfg,
		cursor:     -1,
		viewport:   viewport.New(),
		itemModel:  itemModel,
		mode:       Normal,
		keyMap:     cfg.KeyMap,
		editKeyMap: cfg.EditKeyMap,
	}
	itemModel.AddListener(m)

	m.UpdateViewport()
	return m
}

// Row represents one line in the table.
type Row []string

// Column defines the table structure.
type Column struct {
	Title string
	Width int
}

func AsColumns(c []layout.Cell) []Column {
	cols := make([]Column, len(c))
	for i, cell := range c {
		cols[i] = Column{Title: cell.Title, Width: cell.Size}
	}
	return cols
}

// KeyMap defines keybindings. It satisfies to the help.KeyMap interface, which
// is used to render the help menu.
type KeyMap struct {
	LineUp       key.Binding
	LineDown     key.Binding
	PageUp       key.Binding
	PageDown     key.Binding
	HalfPageUp   key.Binding
	HalfPageDown key.Binding
	GotoTop      key.Binding
	GotoBottom   key.Binding
	Deselect     key.Binding
	MenuRequest  key.Binding
}

// ShortHelp implements the KeyMap interface.
func (km KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{km.LineUp, km.LineDown}
}

// FullHelp implements the KeyMap interface.
func (km KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{km.LineUp, km.LineDown, km.GotoTop, km.GotoBottom},
		{km.PageUp, km.PageDown, km.HalfPageUp, km.HalfPageDown},
	}
}

type EditKeyMap struct {
	Cancel key.Binding
	Submit key.Binding
}

// ShortHelp implements the KeyMap interface.
func (km EditKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{km.Cancel, km.Submit}
}

// FullHelp implements the KeyMap interface.
func (km EditKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{km.Cancel, km.Submit}}
}

func (m *Model[T, K]) KeyMap() help.KeyMap {
	return m.keyMap
}

func (m *Model[T, K]) Update(msg tea.Msg) tea.Cmd {
	if !m.focus {
		return nil
	}

	if m.mode == Edit {
		switch msg := msg.(type) {
		case tea.KeyPressMsg:
			switch {
			case key.Matches(msg, m.editKeyMap.Submit):
				return m.endEdit(true)
			case key.Matches(msg, m.editKeyMap.Cancel):
				return m.endEdit(false)
			}
		}
		var cmd tea.Cmd
		m.editState.editInput, cmd = m.editState.editInput.Update(msg)

		if inputErr := m.editState.editInput.Err; m.editState.lastError != inputErr { //nolint:errorlint
			styles := m.config.Styles.Style().CellEditor
			if inputErr != nil {
				styles.Focused.Text = styles.Focused.Text.Inherit(m.config.Styles.Style().CellEditError)
			}
			// Note: SetStyles resets the cursor blink state, so only call this as
			// needed, not before each render
			m.editState.editInput.SetStyles(styles)

			m.editState.lastError = inputErr
		}
		m.UpdateViewport()
		return cmd
	}

	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, m.keyMap.LineUp):
			m.MoveUp(1)
		case key.Matches(msg, m.keyMap.LineDown):
			m.MoveDown(1)
		case key.Matches(msg, m.keyMap.PageUp):
			m.MoveUp(m.viewport.Height())
		case key.Matches(msg, m.keyMap.PageDown):
			m.MoveDown(m.viewport.Height())
		case key.Matches(msg, m.keyMap.HalfPageUp):
			m.MoveUp(m.viewport.Height() / 2) //nolint:mnd
		case key.Matches(msg, m.keyMap.HalfPageDown):
			m.MoveDown(m.viewport.Height() / 2) //nolint:mnd
		case key.Matches(msg, m.keyMap.GotoTop):
			m.GotoTop()
		case key.Matches(msg, m.keyMap.GotoBottom):
			m.GotoBottom()
		case key.Matches(msg, m.keyMap.Deselect):
			m.cursor = -1
			m.UpdateViewport()
		case key.Matches(msg, m.keyMap.MenuRequest):
			if m.cursor != -1 {
				global := m.Parent().TranslateLocalToGlobalPos(
					uv.Pos(m.config.Styles.Style().Border.GetBorderLeftSize(), m.config.Styles.Style().Border.GetBorderTopSize()+1+m.cursor))
				if m.config.OnRowMenuRequested != nil {
					return m.config.OnRowMenuRequested(m, global, m.cursor)
				}
			}
		}
	case tea.MouseClickMsg:
		global := uv.Pos(msg.X, msg.Y)
		local, inBounds := m.Parent().TranslateGlobalToLocalPos(global)
		if !inBounds {
			return nil
		}

		if local.X >= m.config.Styles.Style().Border.GetBorderLeftSize() &&
			local.X <= m.Width()-m.config.Styles.Style().Border.GetBorderRightSize()-1 &&
			local.Y >= m.config.Styles.Style().Border.GetBorderTopSize()+1 { // +1 for the header
			// find out what row was clicked on
			if row := m.start + (local.Y - 2); row < m.end {
				m.SetCursor(row)
				switch msg.Button {
				case tea.MouseLeft:
				case tea.MouseRight:
					if m.config.OnRowMenuRequested != nil {
						return m.config.OnRowMenuRequested(m, global, row)
					}
				}
			} else {
				m.cursor = -1
				m.UpdateViewport()
			}
		}
	}

	return nil
}

// Focused returns the focus state of the table.
func (m *Model[T, K]) Focused() bool {
	return m.focus
}

// Focus focuses the table, allowing the user to move around the rows and
// interact.
func (m *Model[T, K]) Focus() tea.Cmd {
	m.focus = true
	m.UpdateViewport()
	return nil
}

// Blur blurs the table, preventing selection or movement.
func (m *Model[T, K]) Blur() tea.Cmd {
	m.focus = false
	// If editing was in progress, cancel it
	if m.mode == Edit {
		return m.endEdit(false)
	}
	m.UpdateViewport()
	return nil
}

// View renders the component.
func (m *Model[T, K]) View() uv.Drawable {
	border := m.config.Styles.Style().Border
	if m.focus {
		border = m.config.Styles.Style().BorderFocused
	}

	return uv.NewStyledString(
		style.RenderBorderTitles(
			border.Render(m.headersView()+"\n"+m.viewport.View()),
			border.GetBorderStyle(),
			m.config.BorderTitleLeft,
			m.config.BorderTitleRight))
}

func (m *Model[T, K]) OnIndexUpdate(begin, end models.Index, items []T) {
	newRows := make([]Row, len(items))
	for i, item := range items {
		newRows[i] = Row(m.itemModel.BuildRow(item))
	}
	if int(begin) == len(m.rows) && int(end) == len(m.rows) {
		// append
		m.rows = append(m.rows, newRows...)
	} else {
		m.rows = slices.Replace(m.rows, int(begin), int(end), newRows...)
	}
	m.UpdateViewport()
}

// UpdateViewport updates the list content based on the previously defined
// columns and rows.
func (m *Model[T, K]) UpdateViewport() {
	renderedRows := make([]string, 0, len(m.rows))

	// Render only rows from: m.cursor-m.viewport.Height to: m.cursor+m.viewport.Height
	// Constant runtime, independent of number of rows in a table.
	// Limits the number of renderedRows to a maximum of 2*m.viewport.Height
	if m.cursor >= 0 {
		m.start = clamp(m.cursor-m.viewport.Height(), 0, m.cursor)
	} else {
		m.start = 0
	}
	m.end = clamp(m.cursor+m.viewport.Height(), m.cursor, len(m.rows))
	for i := m.start; i < m.end; i++ {
		renderedRows = append(renderedRows, m.renderRow(i))
	}

	m.viewport.SetContent(
		lipgloss.JoinVertical(lipgloss.Left, renderedRows...),
	)
}

func (m *Model[T, K]) OnResized(w, h int) {
	m.viewport.SetWidth(w - m.config.Styles.Style().Border.GetHorizontalFrameSize())
	m.viewport.SetHeight(h - m.config.Styles.Style().Border.GetVerticalFrameSize() - 1)
	m.cols = AsColumns(m.config.ColumnLayout.Resized(m.viewport.Width()))
	m.UpdateViewport()
}

// Height returns the viewport height of the table.
func (m *Model[T, K]) Height() int {
	return m.viewport.Height()
}

// Width returns the viewport width of the table.
func (m *Model[T, K]) Width() int {
	return m.viewport.Width()
}

func (m *Model[T, K]) SizeHint() (int, int) {
	w := 0
	h := len(m.rows) + 1
	for _, col := range m.cols {
		if col.Width > 0 {
			w += col.Width
		} else {
			w += lipgloss.Width(col.Title)
		}
		w += m.config.Styles.Style().Header.GetHorizontalFrameSize()
	}
	fw, fh := m.config.Styles.Style().Border.GetFrameSize()
	return w + fw, h + fh
}

// Cursor returns the index of the selected row.
func (m *Model[T, K]) Cursor() int {
	return m.cursor
}

// SetCursor sets the cursor position in the table.
func (m *Model[T, K]) SetCursor(n int) {
	m.cursor = clamp(n, 0, len(m.rows)-1)
	m.UpdateViewport()
}

// MoveUp moves the selection up by any number of rows.
// It can not go above the first row.
func (m *Model[T, K]) MoveUp(n int) {
	m.cursor = clamp(m.cursor-n, 0, len(m.rows)-1)

	offset := m.viewport.YOffset()
	switch {
	case m.start == 0:
		offset = clamp(offset, 0, m.cursor)
	case m.start < m.viewport.Height():
		offset = clamp(clamp(offset+n, 0, m.cursor), 0, m.viewport.Height())
	case offset >= 1:
		offset = clamp(offset+n, 1, m.viewport.Height())
	}
	m.viewport.SetYOffset(offset)
	m.UpdateViewport()
}

// MoveDown moves the selection down by any number of rows.
// It can not go below the last row.
func (m *Model[T, K]) MoveDown(n int) {
	m.cursor = clamp(m.cursor+n, 0, len(m.rows)-1)
	m.UpdateViewport()

	offset := m.viewport.YOffset()
	switch {
	case m.end == len(m.rows) && offset > 0:
		offset = clamp(offset-n, 1, m.viewport.Height())
	case m.cursor > (m.end-m.start)/2 && offset > 0:
		offset = clamp(offset-n, 1, m.cursor)
	case offset > 1:
	case m.cursor > offset+m.viewport.Height()-1:
		offset = clamp(offset+1, 0, 1)
	}
	m.viewport.SetYOffset(offset)
}

// GotoTop moves the selection to the first row.
func (m *Model[T, K]) GotoTop() {
	m.MoveUp(m.cursor)
}

// GotoBottom moves the selection to the last row.
func (m *Model[T, K]) GotoBottom() {
	m.MoveDown(len(m.rows))
}

func (m *Model[T, K]) headersView() string {
	if len(m.cols) == 0 {
		return ""
	}
	s := make([]string, 0, len(m.cols))
	style := m.config.Styles.Style().Header
	for _, col := range m.cols {
		if col.Width <= 0 {
			continue
		}
		renderedCell := style.Width(col.Width).Render(ansi.Truncate(col.Title, col.Width-style.GetHorizontalPadding(), "…"))
		s = append(s, renderedCell)
	}
	return lipgloss.JoinHorizontal(lipgloss.Left, s...)
}

func (m *Model[T, K]) GetRow(row int) []string {
	return m.rows[row]
}

func (m *Model[T, K]) GetItem(row int) T {
	return m.itemModel.Data(models.Index(row))
}

func (m *Model[T, K]) beginEdit(state editState) tea.Cmd {
	m.mode = Edit
	m.cursor = -1
	m.focus = true // XXX this should already be true I think
	m.editState = state

	// Calling Focus() here affects the next call to UpdateViewport(). It also
	// returns a command to schedule the next cursor blink message, but Focus()
	// itself should be called beforehand to avoid an initial update delay
	focusCmd := m.editState.editInput.Focus()
	m.UpdateViewport()
	m.editState.interceptor = &messages.ModalInterceptor{
		Update: m.Update,
		KeyMap: m.editKeyMap,
	}
	return tea.Sequence(
		messages.ModalAcquire(m.editState.interceptor),
		focusCmd)
}

func (m *Model[T, K]) endEdit(submit bool) tea.Cmd {
	if submit && m.editState.editInput.Err == nil {
		m.editState.onSubmit(m.editState.editInput.Value())
	}
	m.editState.editInput.Blur()
	interceptor := m.editState.interceptor
	m.editState = editState{}
	m.mode = Normal
	m.UpdateViewport()
	return messages.ModalRelease(interceptor, false)
}

type EditFunc = func(cellContents string, textinput *textinput.Model) (onSubmit func(text string))

func (m *Model[T, K]) Edit(row, col int, editFunc EditFunc) tea.Cmd {
	cellContents := ansi.Strip(m.rows[row][col])
	input := textinput.New()
	input.SetStyles(m.config.Styles.Style().CellEditor)
	onSubmit := editFunc(cellContents, &input)
	return m.beginEdit(editState{
		editInput: input,
		row:       row,
		col:       col,
		onSubmit:  onSubmit,
	})
}

func (m *Model[T, K]) renderRow(r int) string {
	if len(m.cols) == 0 {
		return ""
	}
	cells := make([]string, 0, len(m.cols))
	for c, value := range m.rows[r] {
		if m.cols[c].Width <= 0 {
			continue
		}
		cellWidth := m.cols[c].Width
		style := m.config.Styles.Style().Cell.Width(cellWidth).MaxWidth(cellWidth)
		if cs, ok := m.config.Styles.Style().ColumnStyles[c]; ok {
			style = style.Inherit(cs(value))
		}

		if r == m.cursor && m.focus {
			style = style.Inherit(m.config.Styles.Style().Selected)
		}
		renderedCell := style.Render(ansi.Truncate(value, cellWidth-style.GetHorizontalPadding(), "…"))
		cells = append(cells, renderedCell)
	}

	if m.mode == Edit && m.editState.row == r && m.editState.col < len(cells) {
		cellWidth := m.cols[m.editState.col].Width
		style := m.config.Styles.Style().Cell.Inherit(m.config.Styles.Style().Selected).
			Width(cellWidth).MaxWidth(cellWidth)
		m.editState.editInput.SetWidth(cellWidth - style.GetHorizontalPadding())
		cells[m.editState.col] = style.Render(m.editState.editInput.View())
	}

	row := lipgloss.JoinHorizontal(lipgloss.Top, cells...)

	return row
}

func clamp(v, low, high int) int {
	return min(max(v, low), high)
}
