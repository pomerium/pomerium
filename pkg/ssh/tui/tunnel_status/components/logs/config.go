package logs

import (
	"charm.land/lipgloss/v2"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/logviewer"
)

type Config struct {
	Styles *style.ReactiveStyles[Styles]
	Options
}

type Styles struct {
	logviewer.Styles
	Warning lipgloss.Style
	Error   lipgloss.Style
}

type Options struct {
	Title      string
	KeyMap     logviewer.KeyMap
	Scrollback int
}

func DefaultStyles(theme *style.Theme) Styles {
	return Styles{
		Styles:  logviewer.NewStyles(theme, theme.Colors.Accent4),
		Warning: theme.TextWarning,
		Error:   theme.TextError,
	}
}
