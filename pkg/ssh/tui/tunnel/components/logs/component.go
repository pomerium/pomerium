package logs

import (
	"fmt"

	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/components"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/logviewer"
)

const (
	Type string = "logs"
)

type ComponentFactory struct {
	config Config
}

// NewWidget implements components.ComponentFactory.
func (c *ComponentFactory) NewWidget(component components.Component) core.Widget {
	return core.NewWidget(component.ID(), logviewer.NewModel(logviewer.Config{
		Styles: style.Bind(c.config.Styles, func(base *Styles, _ style.NewStyleFunc) logviewer.Styles {
			return base.Styles
		}),
		Options: logviewer.Options{
			KeyMap:           logviewer.DefaultKeyMap,
			BorderTitleLeft:  c.config.Title,
			BorderTitleRight: fmt.Sprintf("[%s]", component.Mnemonic()),
			ShowTimestamp:    true,
			BufferSize:       c.config.Scrollback,
		},
	}))
}

func NewComponentFactory(config Config) components.ComponentFactory {
	return &ComponentFactory{
		config: config,
	}
}

var _ components.ComponentFactory = (*ComponentFactory)(nil)
