package help

import (
	"charm.land/bubbles/v2/help"
	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
)

type KeyMap = help.KeyMap

type Model struct {
	core.BaseModel
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
	hm.Model.SetWidth(w)
}

func (hm *Model) Focused() bool       { return false }
func (hm *Model) Focus() tea.Cmd      { return nil }
func (hm *Model) Blur() tea.Cmd       { return nil }
func (hm *Model) KeyMap() help.KeyMap { return hm.DisplayedKeyMap }

func NewModel(config Config) *Model {
	return &Model{
		Model: help.Model{
			ShortSeparator: config.Options.ShortSeparator,
			FullSeparator:  config.Options.FullSeparator,
			Ellipsis:       config.Options.Ellipsis,
			Styles:         config.Styles,
		},
	}
}
