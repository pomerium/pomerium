package menu

import (
	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
)

func ShowMenu(anchor uv.Position, entries []Entry) tea.Cmd {
	return func() tea.Msg {
		return ShowMsg{
			Anchor:  anchor,
			Entries: entries,
		}
	}
}

type ShowMsg struct {
	Anchor  uv.Position
	Entries []Entry
}

type HideMsg struct{}

func HideMenu() tea.Msg {
	return HideMsg{}
}
