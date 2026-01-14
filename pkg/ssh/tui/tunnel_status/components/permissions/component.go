package permissions

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core/layout"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel_status/components"
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
	config    Config
	itemModel *models.PermissionModel
}

// NewWidget implements components.ComponentFactory.
func (c *ComponentFactory) NewWidget(component components.Component, theme *style.Theme) core.Widget {
	styles := c.config.Styles(theme)
	return core.NewWidget(
		component.ID(),
		table.NewModel(TableConfig{
			Styles: styles.Styles,
			Options: table.Options{
				ColumnLayout: layout.NewDirectionalLayout([]layout.Cell{
					PermsColHostname: {Title: "Hostname", Size: -1, Style: styles.ColumnStyles["Hostname"]},
					PermsColPort:     {Title: "Port", Size: 8 + 1, Style: styles.ColumnStyles["Port"]},
					PermsColRoutes:   {Title: "Routes", Size: 7 + 1 + 1, Style: styles.ColumnStyles["Routes"]},
				}),
				KeyMap:           table.DefaultKeyMap,
				BorderTitleLeft:  c.config.Title,
				BorderTitleRight: fmt.Sprintf("[%s]", component.Mnemonic()),
			},
			Events: TableEvents{
				OnRowMenuRequested: func(self *TableModel, globalPos uv.Position, index int) tea.Cmd {
					return menu.ShowMenu(globalPos, c.config.RowContextOptions(self, index))
				},
			},
		}, c.itemModel),
	)
}

func NewComponentFactory(config Config, itemModel *models.PermissionModel) components.ComponentFactory {
	return &ComponentFactory{
		config:    config,
		itemModel: itemModel,
	}
}

var _ components.ComponentFactory = (*ComponentFactory)(nil)
