package help

import (
	"charm.land/bubbles/v2/help"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Widget = core.Widget[*Model]

type Styles = help.Styles

type Config struct {
	Styles
	Options
}

func NewStyles(theme *style.Theme) Styles {
	return Styles{
		Ellipsis:       theme.HelpSeparator,
		ShortKey:       theme.HelpKey,
		ShortDesc:      theme.HelpDesc,
		ShortSeparator: theme.HelpSeparator,
		FullKey:        theme.HelpKey,
		FullDesc:       theme.HelpDesc,
		FullSeparator:  theme.HelpSeparator,
	}
}

type Options struct {
	ShortSeparator string
	FullSeparator  string
	Ellipsis       string
}

var DefaultOptions = Options{
	ShortSeparator: " • ",
	FullSeparator:  "    ",
	Ellipsis:       "…",
}
