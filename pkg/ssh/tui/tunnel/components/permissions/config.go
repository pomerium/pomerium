package permissions

import (
	"strings"

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
		Styles: table.NewStyles(theme, theme.Colors.Accent2, map[int]func(s string, base lipgloss.Style) lipgloss.Style{
			PermsColHostname: func(s string, base lipgloss.Style) lipgloss.Style {
				if s == "(all)" {
					return base.Faint(true)
				}
				return base
			},
			PermsColPort: func(s string, base lipgloss.Style) lipgloss.Style {
				if strings.HasPrefix(s, "D ") {
					return base.Foreground(theme.Colors.TextNotice)
				}
				return base
			},
		}),
	}
}
