package messages

import (
	tea "charm.land/bubbletea/v2"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/help"
)

type ModalInterceptor struct {
	Update            func(tea.Msg) tea.Cmd
	KeyMap            help.KeyMap // optional
	Scrim             bool
	MouseModeOverride *tea.MouseMode
}

type ModalAcquireMsg struct {
	Interceptor *ModalInterceptor
}

type ModalReleaseMsg struct {
	Interceptor            *ModalInterceptor
	IgnoreNextMouseRelease bool
}

func ModalAcquire(interceptor *ModalInterceptor) tea.Cmd {
	return func() tea.Msg {
		return ModalAcquireMsg{
			Interceptor: interceptor,
		}
	}
}

func ModalRelease(interceptor *ModalInterceptor, ignoreNextMouseRelease bool) tea.Cmd {
	return func() tea.Msg {
		return ModalReleaseMsg{
			Interceptor:            interceptor,
			IgnoreNextMouseRelease: ignoreNextMouseRelease,
		}
	}
}
