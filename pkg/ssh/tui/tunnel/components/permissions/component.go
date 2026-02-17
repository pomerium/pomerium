package permissions

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"

	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/components"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/menu"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/table"
)

const (
	Type string = "permissions"
)

const (
	PermsColHostname = iota
	PermsColPort
	PermsColRoutes
)

type (
	TableModel  = table.Model[models.Permission, uint64]
	TableConfig = table.Config[models.Permission, uint64]
	TableEvents = table.Events[models.Permission, uint64]
)

type ComponentFactory struct {
	config Config
}

// NewWidget implements components.ComponentFactory.
func (c *ComponentFactory) NewWidget(component components.Component) core.Widget {
	return core.NewWidget(
		component.ID(),
		table.NewModel(TableConfig{
			Styles: style.Bind(c.config.Styles, func(base *Styles, _ style.NewStyleFunc) table.Styles {
				return base.Styles
			}),
			Options: table.Options{
				ColumnLayout: layout.NewDirectionalLayout([]layout.Cell{
					PermsColHostname: {Title: "Hostname", Size: -1},
					PermsColPort:     {Title: "Port", Size: 8 + 1},
					PermsColRoutes:   {Title: "Routes", Size: 7 + 1 + 1},
				}),
				BorderTitleLeft:  c.config.Title,
				BorderTitleRight: fmt.Sprintf("[%s]", component.Mnemonic()),
			},
			Events: TableEvents{
				OnRowMenuRequested: func(self *TableModel, globalPos uv.Position, index int) tea.Cmd {
					return menu.ShowMenu(menu.Options{
						Anchor:  globalPos,
						Entries: c.config.GetRowContextOptions(self, index),
					})
				},
			},
		}),
	)
}

func NewComponentFactory(config Config) components.ComponentFactory {
	return &ComponentFactory{
		config: config,
	}
}

var _ components.ComponentFactory = (*ComponentFactory)(nil)
