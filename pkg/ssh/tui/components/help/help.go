package help

import (
	"charm.land/bubbles/v2/help"
	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
)

type Widget = core.Widget[*Model]

type KeyMap = help.KeyMap

type Model struct {
	help.Model
	DisplayedKeyMap KeyMap
}

func (hm *Model) View() uv.Drawable {
	return uv.NewStyledString(hm.Model.View(hm.DisplayedKeyMap))
}

func (hm *Model) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	hm.Model, cmd = hm.Model.Update(msg)
	return cmd
}

func (hm *Model) OnResized(w, _ int) {
	hm.Model.Width = w
}

func (hm *Model) Focused() bool       { return false }
func (hm *Model) Focus()              {}
func (hm *Model) Blur()               {}
func (hm *Model) KeyMap() help.KeyMap { return hm.DisplayedKeyMap }

func NewModel(theme *style.Theme) *Model {
	return &Model{
		Model: help.Model{
			ShortSeparator: " • ",
			FullSeparator:  "    ",
			Ellipsis:       "…",
			Styles: help.Styles{
				Ellipsis:       theme.HelpSeparator,
				ShortKey:       theme.HelpKey,
				ShortDesc:      theme.HelpDesc,
				ShortSeparator: theme.HelpSeparator,
				FullKey:        theme.HelpKey,
				FullDesc:       theme.HelpDesc,
				FullSeparator:  theme.HelpSeparator,
			},
		},
	}
}
