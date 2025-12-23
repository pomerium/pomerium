package core

import (
	"image"

	"charm.land/bubbles/v2/help"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
)

type (
	KeyMap = help.KeyMap

	Model interface {
		View() uv.Drawable
		Update(tea.Msg) tea.Cmd
		Focused() bool
		Focus()
		Blur()
		KeyMap() KeyMap
		OnResized(width, height int)
		SetParentInterface(ParentInterface)
	}

	ParentInterface interface {
		TranslateLocalToGlobalPos(localPos uv.Position) uv.Position
		TranslateGlobalToLocalPos(globalPos uv.Position) uv.Position
	}
)

type BaseModel struct {
	parent ParentInterface
}

func (bm *BaseModel) SetParentInterface(p ParentInterface) {
	bm.parent = p
}

func (bm *BaseModel) Parent() ParentInterface {
	return bm.parent
}

type Resizable interface {
	Bounds() uv.Rectangle
	SetBounds(uv.Rectangle)
}

type Widget[M Model] struct {
	*lipgloss.Layer
	Model  M
	Hidden bool
}

func (w *Widget[M]) SetBounds(bounds uv.Rectangle) {
	// BUG: the layer X() and Y() functions ADD to the existing coordinates,
	// instead of replacing them. To work around this, apply a negative offset
	// with the current value
	w.Layer.
		X(-w.Layer.GetX() + bounds.Min.X).
		Y(-w.Layer.GetY() + bounds.Min.Y).
		Width(bounds.Dx()).
		Height(bounds.Dy())
	w.Model.OnResized(w.GetWidth(), w.GetHeight())
}

func (w *Widget[M]) Draw(scr uv.Screen, area image.Rectangle) {
	if w.Hidden {
		return
	}
	w.Model.View().Draw(scr, area)
}

type parentInterfaceImpl struct {
	widget Resizable
}

func (p *parentInterfaceImpl) TranslateLocalToGlobalPos(localPos uv.Position) uv.Position {
	return p.widget.Bounds().Min.Add(localPos)
}

func (p *parentInterfaceImpl) TranslateGlobalToLocalPos(globalPos uv.Position) uv.Position {
	return globalPos.Sub(p.widget.Bounds().Min)
}

func NewWidget[M Model](id string, m M) *Widget[M] {
	w := &Widget[M]{
		Layer: (&lipgloss.Layer{}).ID(id),
		Model: m,
	}
	m.SetParentInterface(&parentInterfaceImpl{w})
	w.Layer.SetContent(w)
	return w
}
