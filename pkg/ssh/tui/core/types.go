package core

import (
	"image"
	"slices"

	"charm.land/bubbles/v2/help"
	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
)

type StatusFlags uint32

const (
	SkipNextRender StatusFlags = 1 << iota
)

type Status struct {
	Cmd   tea.Cmd
	Flags StatusFlags
}

func Cmd(cmd tea.Cmd) Status {
	return Status{Cmd: cmd}
}

var NilCmd = Status{}

type (
	KeyMap = help.KeyMap

	Model interface {
		View() uv.Drawable
		Update(tea.Msg) tea.Cmd
		Focused() bool
		Focus() tea.Cmd
		Blur() tea.Cmd
		KeyMap() KeyMap
		SizeHint() (width, height int)
		OnResized(width, height int)
		SetParentInterface(ParentInterface)
	}

	ParentInterface interface {
		TranslateLocalToGlobalPos(localPos uv.Position) uv.Position
		TranslateGlobalToLocalPos(globalPos uv.Position) (localPos uv.Position, inBounds bool)
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
	uv.Drawable
	Resizable
	ID() string
	Model() Model
	Hidden() bool
	SetHidden(bool)
}

type widget struct {
	id     string
	bounds uv.Rectangle
	model  Model
	hidden bool
}

func (w *widget) ID() string {
	return w.id
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
	return w.bounds
}

func (w *widget) SetBounds(bounds uv.Rectangle) {
	w.bounds = bounds
	w.Model().OnResized(bounds.Dx(), bounds.Dy())
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

func (p *parentInterfaceImpl) TranslateGlobalToLocalPos(globalPos uv.Position) (uv.Position, bool) {
	localBounds := p.widget.Bounds()
	local := globalPos.Sub(localBounds.Min)
	return local, globalPos.In(localBounds)
}

func NewWidget[M Model](id string, m M) Widget {
	w := &widget{
		id:    id,
		model: m,
	}
	m.SetParentInterface(&parentInterfaceImpl{w})
	return w
}

type DeviceAttributes struct {
	ClipboardSupport bool
}

// RenderOrder describes a list of rendered widgets. Assumed to be sorted
// in the order the widgets were composited, so entries ordered later in the
// list have a higher z-index.
type RenderOrder []RenderInfo

func (order RenderOrder) HitTest(x, y int) RenderInfo {
	for _, wr := range slices.Backward(order) {
		if uv.Pos(x, y).In(wr.Bounds) {
			return wr
		}
	}
	return RenderInfo{}
}

type RenderInfo struct {
	ID     string
	Bounds uv.Rectangle
}

func (info *RenderInfo) Empty() bool {
	return info.ID == ""
}
