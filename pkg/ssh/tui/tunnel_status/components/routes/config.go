package routes

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
		Styles: table.NewStyles(theme, theme.Colors.Accent3),
		ColumnStyles: map[string]func(s string) lipgloss.Style{
			"Status": func(s string) lipgloss.Style {
				switch s {
				case "ACTIVE":
					return theme.TextStatusHealthy
				case "INACTIVE":
					return theme.TextStatusUnknown
				case "--":
					return theme.TextStatusUnknown
				default:
					return lipgloss.Style{}
				}
			},
			"Health": func(s string) lipgloss.Style {
				switch s {
				case "HEALTHY":
					return theme.TextStatusHealthy
				case "UNHEALTHY", "ERROR":
					return theme.TextStatusUnhealthy
				case "DEGRADED":
					return theme.TextStatusDegraded
				case "UNKNOWN", "--":
					return theme.TextStatusUnknown
				default:
					return lipgloss.Style{}
				}
			},
		},
	}
}
