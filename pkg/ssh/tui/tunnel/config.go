package tunnel

import (
	"image/color"

	"charm.land/bubbles/v2/key"
	"charm.land/lipgloss/v2"
	"github.com/zeebo/xxh3"

	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
	"github.com/pomerium/pomerium/pkg/ssh/tui/tunnel/components"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/dialog"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/header"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/help"
	"github.com/pomerium/pomerium/pkg/ssh/tui/widgets/menu"
)

type Config struct {
	Styles *style.ReactiveStyles[Styles]
	Options
}

type Styles struct {
	BackgroundColor color.Color
	WidgetStyles
	HeaderSegments HeaderSegmentStyles
}

type WidgetStyles struct {
	Help        help.Styles
	ContextMenu menu.Styles
	Dialog      dialog.Styles
	DialogText  lipgloss.Style
	MotdText    lipgloss.Style
	Logs        LogsStyles
}

type LogsStyles struct {
	Warning lipgloss.Style
	Error   lipgloss.Style
}

type HeaderSegmentStyles struct {
	Colors style.Colors
}

type HeaderOptions struct {
	LeftAlignedSegments  func(*style.ReactiveStyles[Styles]) []header.Segment
	RightAlignedSegments func(*style.ReactiveStyles[Styles]) []header.Segment
}

type HelpOptions struct{}

type Options struct {
	KeyMap     KeyMap
	Header     HeaderOptions
	Help       HelpOptions
	Components []components.Component
	FetchMotd  func(session models.Session) *MotdOptions
}

type MotdStartupBehavior int

const (
	// The MOTD will not be displayed on startup
	None MotdStartupBehavior = iota
	// The MOTD will be displayed on startup unless the user has already seen
	// the current message. Only the most recent message each user has seen is
	// tracked.
	ShowOnceOnStart
	// The MOTD will always be displayed on startup.
	ShowAlwaysOnStart
)

type MotdOptions struct {
	Text            string
	StartupBehavior MotdStartupBehavior
	ActionRequired  bool
	Buttons         []dialog.ButtonConfig // If empty, a single "Close" button is used
}

func (o *MotdOptions) TextHash() uint64 {
	return xxh3.HashString(o.Text)
}

// ReopenEnabled determines whether or not the MOTD can be reopened after it is
// closed the first time, so that the user can view the message again.
//
// Because the MOTD can be used as a way to prompt for some initial user action
// on connect, it may not always make sense to allow it to be re-openable
// (for example if the configured button actions have side effects).
//
// The MOTD cannot be re-opened if either:
//   - Any custom buttons are configured
//   - ActionRequired is set to true
func (o *MotdOptions) ReopenEnabled() bool {
	return len(o.Buttons) == 0 && !o.ActionRequired
}

type KeyMap struct {
	FocusNext  key.Binding
	FocusPrev  key.Binding
	Quit       key.Binding
	ReopenMotd key.Binding
}

// FullHelp implements help.KeyMap.
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Quit, k.FocusNext, k.FocusPrev, k.ReopenMotd},
	}
}

// ShortHelp implements help.KeyMap.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Quit, k.FocusNext, k.FocusPrev}
}

var DefaultKeyMap = KeyMap{
	FocusNext: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "select next panel"),
	),
	FocusPrev: key.NewBinding(
		key.WithKeys("shift+tab"),
		key.WithHelp("shift-tab", "select prev panel"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	ReopenMotd: key.NewBinding(
		key.WithKeys("m"),
		key.WithHelp("m", "show server motd"),
	),
}

func NewStyles(theme *style.Theme) Styles {
	s := Styles{
		BackgroundColor: theme.Colors.WindowBackground,
		HeaderSegments: HeaderSegmentStyles{
			Colors: theme.Colors,
		},
		WidgetStyles: WidgetStyles{
			Help:        help.NewStyles(theme),
			ContextMenu: menu.NewStyles(theme),
			Dialog:      dialog.NewStyles(theme),
			Logs: LogsStyles{
				Warning: theme.TextWarning,
				Error:   theme.TextError,
			},
		},
	}
	// Note: dialog text needs a background, otherwise it is rendered incorrectly.
	s.DialogText = theme.TextNormal.Faint(false).Background(s.Dialog.Dialog.GetBackground())
	s.MotdText = s.DialogText.Padding(4, 8, 4, 8)
	return s
}
