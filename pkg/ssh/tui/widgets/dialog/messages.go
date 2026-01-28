package dialog

import (
	tea "charm.land/bubbletea/v2"
)

func ShowDialog(options Options) tea.Cmd {
	return func() tea.Msg {
		return ShowMsg{
			Options: options,
		}
	}
}

type ShowMsg struct {
	Options Options
}
