package table

import (
	"charm.land/lipgloss/v2"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Widget = core.Widget[*Model]

type Config struct {
	Styles
	Options
}

type Styles struct {
	Header        lipgloss.Style
	Cell          lipgloss.Style
	Selected      lipgloss.Style
	Border        lipgloss.Style
	BorderFocused lipgloss.Style
}

type Options struct {
	BorderTitleLeft  string
	BorderTitleRight string
}

func NewStyles(theme *style.Theme, accentColor style.AccentColor) Styles {
	return Styles{
		Header:        lipgloss.NewStyle().Inherit(theme.TableHeader).PaddingLeft(1),
		Cell:          lipgloss.NewStyle().Inherit(theme.TableCell).PaddingLeft(1),
		Selected:      lipgloss.NewStyle().Inherit(theme.TableSelectedCell).PaddingLeft(1),
		Border:        lipgloss.NewStyle().Inherit(theme.Card),
		BorderFocused: lipgloss.NewStyle().Inherit(theme.Card).BorderForeground(accentColor.Normal),
	}
}
