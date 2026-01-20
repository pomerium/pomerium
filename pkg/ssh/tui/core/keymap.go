package core

import (
	"reflect"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
)

func ApplyKeyMapDefaults[T help.KeyMap](keymap *T, defaults T) {
	typ := reflect.TypeFor[T]()
	ontoValue := reflect.ValueOf(keymap).Elem()
	defaultsValue := reflect.ValueOf(defaults)
	for f := range typ.NumField() {
		fieldValue := ontoValue.Field(f)
		if fieldValue.Type() == reflect.TypeFor[key.Binding]() && fieldValue.IsZero() {
			fieldValue.Set(defaultsValue.Field(f))
		}
	}
}

type DynamicKeyMap[K KeyMap] struct {
	base K

	runtime    map[string]key.Binding
	runtimeIds []string

	focusedKeyMap help.KeyMap
	modalKeyMap   help.KeyMap
}

func NewDynamicKeyMap[K help.KeyMap](base K) *DynamicKeyMap[K] {
	return &DynamicKeyMap[K]{
		base:    base,
		runtime: map[string]key.Binding{},
	}
}

func (d *DynamicKeyMap[K]) AddRuntimeBinding(id string, binding key.Binding) {
	if _, ok := d.runtime[id]; ok {
		panic("bug: AddRuntimeBinding called with duplicate key: " + id)
	}
	d.runtimeIds = append(d.runtimeIds, id)
	d.runtime[id] = binding
}

func (d *DynamicKeyMap[K]) Get() *K {
	return &d.base
}

func (d *DynamicKeyMap[K]) Runtime(id string) key.Binding {
	return d.runtime[id]
}

func (d *DynamicKeyMap[K]) SetFocusedKeyMap(km help.KeyMap) {
	d.focusedKeyMap = km
}

func (d *DynamicKeyMap[K]) SetModalKeyMap(km help.KeyMap) {
	d.modalKeyMap = km
}

// FullHelp implements help.KeyMap.
func (d *DynamicKeyMap[K]) FullHelp() [][]key.Binding {
	fh := d.base.FullHelp()
	for _, id := range d.runtimeIds {
		fh[0] = append(fh[0], d.runtime[id])
	}
	if d.modalKeyMap != nil {
		return d.modalKeyMap.FullHelp()
	} else if d.focusedKeyMap != nil {
		focusedFh := d.focusedKeyMap.FullHelp()
		for len(fh) < len(focusedFh) {
			fh = append(fh, []key.Binding{})
		}
		for i, row := range focusedFh {
			fh[i] = append(fh[i], row...)
		}
	}
	return fh
}

// ShortHelp implements help.KeyMap.
func (d *DynamicKeyMap[K]) ShortHelp() []key.Binding {
	sh := d.base.ShortHelp()
	for _, id := range d.runtimeIds {
		sh = append(sh, d.runtime[id])
	}
	if d.modalKeyMap != nil {
		return d.modalKeyMap.ShortHelp()
	} else if d.focusedKeyMap != nil {
		sh = append(sh, d.focusedKeyMap.ShortHelp()...)
	}
	return sh
}
