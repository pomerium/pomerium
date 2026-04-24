package nullable

import (
	"bytes"
	"encoding/json"
)

type Value[T any] struct {
	set   bool
	value T
}

func NewValue[T any](set bool, value T) Value[T] {
	return Value[T]{set: set, value: value}
}

func ValueFromPtr[T any](ptr *T) Value[T] {
	var def T
	if ptr == nil {
		return NewValue(false, def)
	}
	return NewValue(true, *ptr)
}

func (v Value[T]) IsSet() bool {
	return v.set
}

func (v Value[T]) Or(value T) T {
	if v.set {
		return v.value
	}
	return value
}

func (v Value[T]) Value() T {
	return v.value
}

func (v *Value[T]) MarshalJSON() ([]byte, error) {
	if v.set {
		return json.Marshal(v.value)
	}
	return []byte("null"), nil
}

func (v *Value[T]) UnmarshalJSON(data []byte) error {
	var def T
	if bytes.Equal(data, []byte("null")) {
		v.set = false
		v.value = def
	}
	v.set = true
	return json.Unmarshal(data, &v.value)
}
