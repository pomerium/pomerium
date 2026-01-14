package permissions

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/menu"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/table"
)

type Config struct {
	Styles func(*style.Theme) Styles
	Options
}

type Styles struct {
	table.Styles
	ColumnStyles map[string]func(s string) lipgloss.Style
}

type Options struct {
	Title             string
	KeyMap            table.KeyMap
	RowContextOptions func(model *TableModel, row int) []menu.Entry
}

func DefaultStyles(theme *style.Theme) Styles {
	return Styles{
		Styles: table.NewStyles(theme, theme.Colors.Accent2),
		ColumnStyles: map[string]func(s string) lipgloss.Style{
			"Hostname": func(s string) lipgloss.Style {
				if s == "(all)" {
					return lipgloss.NewStyle().Faint(true)
				}
				return lipgloss.Style{}
			},
			"Port": func(s string) lipgloss.Style {
				if strings.HasPrefix(s, "D ") {
					return lipgloss.NewStyle().Foreground(lipgloss.Blue)
				}
				return lipgloss.Style{}
			},
		},
	}
}
