package cli

import (
	"io"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/api"
	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/preferences"
)

type InternalCLI interface {
	Stdin() io.Reader
	Stdout() io.Writer
	Stderr() io.Writer
	PtyInfo() api.SSHPtyInfo
	SendTeaMsg(msg tea.Msg)
	RunProgram(prog *tea.Program) (tea.Model, error)
}

type InternalCLIController interface {
	Configure(root *cobra.Command, cli InternalCLI, ctrl api.ChannelControlInterface)
	DefaultArgs(modeHint extensions_ssh.InternalCLIModeHint) []string
	EventHandlers() models.EventHandlers
	PreferencesStore() preferences.Store
}
