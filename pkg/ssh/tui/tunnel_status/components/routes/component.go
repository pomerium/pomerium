package routes

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
	Type string = "routes"
)

const (
	RoutesColStatus = iota
	RoutesColHealth
	RoutesColRemote
	RoutesColLocal
)

type ComponentFactory struct {
	config    Config
	itemModel *models.RouteModel
}

type (
	TableModel  = table.Model[models.Route, string]
	TableConfig = table.Config[models.Route, string]
	TableEvents = table.Events[models.Route, string]
)

// NewWidget implements components.ComponentFactory.
func (c *ComponentFactory) NewWidget(component components.Component, theme *style.Theme) core.Widget {
	styles := c.config.Styles(theme)
	return core.NewWidget(
		component.ID(),
		table.NewModel(
			TableConfig{
				Styles: styles.Styles,
				Options: table.Options{
					ColumnLayout: layout.NewDirectionalLayout([]layout.Cell{
						RoutesColStatus: {Title: "Status", Size: 10, Style: styles.ColumnStyles["Status"]},
						RoutesColHealth: {Title: "Health", Size: 10, Style: styles.ColumnStyles["Health"]},
						RoutesColRemote: {Title: "Remote", Size: -1, Style: styles.ColumnStyles["Remote"]},
						RoutesColLocal:  {Title: "Local", Size: -1, Style: styles.ColumnStyles["Local"]},
					}),
					KeyMap:           table.DefaultKeyMap,
					EditKeyMap:       table.DefaultEditKeyMap,
					BorderTitleLeft:  c.config.Title,
					BorderTitleRight: fmt.Sprintf("[%s]", component.Mnemonic()),
				},
				Events: TableEvents{
					OnRowMenuRequested: func(self *TableModel, globalPos uv.Position, index int) tea.Cmd {
						return menu.ShowMenu(globalPos, c.config.RowContextOptions(self, index))
					},
				},
			},
			c.itemModel),
	)
}

func NewComponentFactory(config Config, itemModel *models.RouteModel) components.ComponentFactory {
	return &ComponentFactory{
		config:    config,
		itemModel: itemModel,
	}
}

var _ components.ComponentFactory = (*ComponentFactory)(nil)
