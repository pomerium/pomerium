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
		Focus() tea.Cmd
		Blur() tea.Cmd
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

type Widget interface {
	Resizable
	Model() Model
	Layer() *lipgloss.Layer
	Hidden() bool
	SetHidden(bool)
}

type widget struct {
	layer  *lipgloss.Layer
	model  Model
	hidden bool
}

func (w *widget) Layer() *lipgloss.Layer {
	return w.layer
}

func (w *widget) Model() Model {
	return w.model
}

func (w *widget) Hidden() bool {
	return w.hidden
}

func (w *widget) SetHidden(hidden bool) {
	w.hidden = hidden
}

func (w *widget) Bounds() uv.Rectangle {
	return w.layer.Bounds()
}

func (w *widget) SetBounds(bounds uv.Rectangle) {
	// BUG: the layer X() and Y() functions ADD to the existing coordinates,
	// instead of replacing them. To work around this, apply a negative offset
	// with the current value
	w.layer.
		X(-w.layer.GetX() + bounds.Min.X).
		Y(-w.layer.GetY() + bounds.Min.Y).
		Width(bounds.Dx()).
		Height(bounds.Dy())
	w.Model().OnResized(w.layer.GetWidth(), w.layer.GetHeight())
}

func (w *widget) Draw(scr uv.Screen, area image.Rectangle) {
	if w.Hidden() {
		return
	}
	w.model.View().Draw(scr, area)
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

func NewWidget[M Model](id string, m M) Widget {
	w := &widget{
		layer: (&lipgloss.Layer{}).ID(id),
		model: m,
	}
	m.SetParentInterface(&parentInterfaceImpl{w})
	w.layer.SetContent(w)
	return w
}
