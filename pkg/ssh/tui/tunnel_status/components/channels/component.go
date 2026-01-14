package channels

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
	Type string = "channels"
)

const (
	ChannelsColID = iota
	ChannelsColStatus
	ChannelsColHostname
	ChannelsColPath
	ChannelsColClient
	ChannelsColRxBytes
	ChannelsColTxBytes
	ChannelsColDuration
)

type ComponentFactory struct {
	config    Config
	itemModel *models.ChannelModel
}

type (
	TableModel  = table.Model[models.Channel, uint32]
	TableConfig = table.Config[models.Channel, uint32]
	TableEvents = table.Events[models.Channel, uint32]
)

// NewWidget implements components.ComponentFactory.
func (c *ComponentFactory) NewWidget(component components.Component, theme *style.Theme) core.Widget {
	styles := c.config.Styles(theme)
	w := core.NewWidget(component.ID(),
		table.NewModel(
			TableConfig{
				Styles: styles.Styles,
				Options: table.Options{
					ColumnLayout: layout.NewDirectionalLayout([]layout.Cell{
						ChannelsColID:       {Title: "Channel", Size: 7 + 1 + 1, Style: styles.ColumnStyles["Channel"]},
						ChannelsColStatus:   {Title: "Status", Size: 6 + 1, Style: styles.ColumnStyles["Status"]},
						ChannelsColHostname: {Title: "Hostname", Size: -2, Style: styles.ColumnStyles["Hostname"]},
						ChannelsColPath:     {Title: "Path", Size: -2, Style: styles.ColumnStyles["Path"]},
						ChannelsColClient:   {Title: "Client", Size: 21 + 1, Style: styles.ColumnStyles["Client"]},
						ChannelsColRxBytes:  {Title: "Rx Bytes", Size: -1, Style: styles.ColumnStyles["Rx Bytes"]},
						ChannelsColTxBytes:  {Title: "Tx Bytes", Size: -1, Style: styles.ColumnStyles["Tx Bytes"]},
						ChannelsColDuration: {Title: "Duration", Size: -1, Style: styles.ColumnStyles["Duration"]},
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
			c.itemModel,
		))
	return w
}

func NewComponentFactory(config Config, itemModel *models.ChannelModel) components.ComponentFactory {
	return &ComponentFactory{
		config:    config,
		itemModel: itemModel,
	}
}

var _ components.ComponentFactory = (*ComponentFactory)(nil)
