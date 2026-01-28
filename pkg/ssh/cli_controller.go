package ssh

import (
	"github.com/spf13/cobra"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/cli"
	"github.com/pomerium/pomerium/pkg/ssh/cli/commands"
	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/preferences"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type DefaultCLIController struct {
	config           *config.Config
	defaultTheme     *style.Theme
	preferencesStore preferences.Store
}

func NewDefaultCLIController(config *config.Config, defaultTheme *style.Theme) *DefaultCLIController {
	return &DefaultCLIController{
		config:           config,
		defaultTheme:     defaultTheme,
		preferencesStore: preferences.NewInMemoryStore(),
	}
}

// Configure implements InternalCLIController.
func (cc *DefaultCLIController) Configure(root *cobra.Command, ic cli.InternalCLI, ctrl api.ChannelControlInterface) {
	if cc.config.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHRoutesPortal) {
		root.AddCommand(commands.NewPortalCommand(ic, ctrl))
	}
	root.AddCommand(commands.NewLogoutCommand(ic))
	root.AddCommand(commands.NewWhoamiCommand(ic, ctrl))
	root.AddCommand(commands.NewTunnelCommand(ic, ctrl, cc.defaultTheme, cc.preferencesStore))
}

// DefaultArgs implements InternalCLIController.
func (cc *DefaultCLIController) DefaultArgs(modeHint extensions_ssh.InternalCLIModeHint) []string {
	switch modeHint {
	default:
		fallthrough
	case extensions_ssh.InternalCLIModeHint_MODE_DEFAULT:
		if cc.config.Options.IsRuntimeFlagSet(config.RuntimeFlagSSHRoutesPortal) {
			return []string{"portal"}
		}
		return []string{}
	case extensions_ssh.InternalCLIModeHint_MODE_TUNNEL_STATUS:
		return []string{"tunnel"}
	}
}

// EventHandlers implements InternalCLIController.
func (cc *DefaultCLIController) EventHandlers() models.EventHandlers {
	return models.EventHandlers{
		RouteDataModelEventHandlers: models.RouteModelEventHandlers{
			OnRouteEditRequest: func(route models.Route) {
				_ = route
			},
		},
	}
}

// PreferencesStore implements InternalCLIController.
func (cc *DefaultCLIController) PreferencesStore() preferences.Store {
	return cc.preferencesStore
}

var _ cli.InternalCLIController = (*DefaultCLIController)(nil)
