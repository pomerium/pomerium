package channels

import (
	"charm.land/lipgloss/v2"

	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/menu"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/table"
)

type Config struct {
	Styles *style.ReactiveStyles[Styles]
	Options
}

type Styles struct {
	table.Styles
}

type Options struct {
	Title             string
	KeyMap            table.KeyMap
	RowContextOptions func(model *TableModel, row int) []menu.Entry
}

func (op *Options) GetRowContextOptions(model *TableModel, row int) []menu.Entry {
	if op.RowContextOptions == nil {
		return nil
	}
	return op.RowContextOptions(model, row)
}

func DefaultStyles(theme *style.Theme) Styles {
	return Styles{
		Styles: table.NewStyles(theme, theme.Colors.Accent1, map[int]func(s string, base lipgloss.Style) lipgloss.Style{
			ChannelsColStatus: func(s string, base lipgloss.Style) lipgloss.Style {
				switch s {
				case "OPEN":
					return theme.TextStatusHealthy.Inherit(base)
				case "CLOSED":
					return theme.TextStatusDegraded.Inherit(base)
				default:
					return base
				}
			},
			ChannelsColClient: func(s string, base lipgloss.Style) lipgloss.Style {
				if s == "envoy_health_check" {
					return theme.TextNotice.
						Transform(func(string) string { return "Health Check" })
				}
				return base
			},
		}),
	}
}
