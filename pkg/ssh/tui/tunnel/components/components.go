package components

import (
	"github.com/pomerium/pomerium/pkg/ssh/tui/core"
)

type Component interface {
	Type() string
	ID() string
	Mnemonic() string
	StartsHidden() bool
	RowHint() int
	ColumnHint() int
	LayoutWidth() int
	LayoutHeight() int
}

type ComponentFactoryRegistry interface {
	// Creates a new widget for the given component using the factory matching
	// the component's type.
	// Shortcut for GetFactory(component.Type()).NewWidget(...), but automatically
	// injects the previously stored Theme into the call to NewWidget, and applies
	// default visibility rules from the component config.
	NewComponentWidget(component Component) core.Widget

	// Gets the component factory for the component with the given type, or panics
	// if no such factory was registered with RegisterFactory.
	GetFactory(typ string) ComponentFactory
	// Sets the component factory for the component with the given type.
	// If a factory for the ID was already registered, it will be replaced.
	RegisterFactory(typ string, factory ComponentFactory)
}

type ComponentWidget interface {
	Component
	core.Widget
}

type ComponentFactory interface {
	NewWidget(component Component) core.Widget
}

type componentFactoryRegistry struct {
	factoriesByID map[string]ComponentFactory
}

// NewComponentWidget implements ComponentFactoryRegistry.
func (c *componentFactoryRegistry) NewComponentWidget(component Component) core.Widget {
	w := c.GetFactory(component.Type()).NewWidget(component)
	if component.StartsHidden() {
		w.SetHidden(true)
	}
	return w
}

// RegisterFactory implements ComponentFactoryRegistry.
func (c *componentFactoryRegistry) RegisterFactory(id string, factory ComponentFactory) {
	c.factoriesByID[id] = factory
}

// GetFactory implements ComponentFactoryRegistry.
func (c *componentFactoryRegistry) GetFactory(id string) ComponentFactory {
	f, ok := c.factoriesByID[id]
	if !ok {
		panic("no registered factory for component with id: " + id)
	}
	return f
}

var _ ComponentFactoryRegistry = (*componentFactoryRegistry)(nil)

func NewComponentFactoryRegistry() ComponentFactoryRegistry {
	return &componentFactoryRegistry{
		factoriesByID: map[string]ComponentFactory{},
	}
}
