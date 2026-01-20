package menu

import (
	tea "charm.land/bubbletea/v2"
)

func ShowMenu(options Options) tea.Cmd {
	if len(options.Entries) == 0 {
		return nil
	}
	return func() tea.Msg {
		return ShowMsg{
			Options: options,
		}
	}
}

type ShowMsg struct {
	Options Options
}
