package channels

import (
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
		Styles: table.NewStyles(theme, theme.Colors.Accent1),
		ColumnStyles: map[string]func(s string) lipgloss.Style{
			"Status": func(s string) lipgloss.Style {
				switch s {
				case "OPEN":
					return theme.TextStatusHealthy
				case "CLOSED":
					return theme.TextStatusDegraded
				default:
					return lipgloss.Style{}
				}
			},
			"Client": func(s string) lipgloss.Style {
				if s == "envoy_health_check" {
					return lipgloss.NewStyle().
						Faint(true).
						Transform(func(string) string { return "Health Check" })
				}
				return lipgloss.Style{}
			},
		},
	}
}
