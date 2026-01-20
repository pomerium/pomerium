package messages

import tea "charm.land/bubbletea/v2"

type ErrorMsg struct {
	Error error
}

func ExitWithError(err error) tea.Cmd {
	return func() tea.Msg {
		return ErrorMsg{
			Error: err,
		}
	}
}
