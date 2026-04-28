package nullable

import (
	"bytes"
	"encoding/json"
	"reflect"

	"gopkg.in/yaml.v3"
)

type Value[T any] struct {
	IsSet bool
	Value T
}

func NewValue[T any](isSet bool, value T) Value[T] {
	return Value[T]{IsSet: isSet, Value: value}
}

func From[T any](value T) Value[T] {
	return NewValue(true, value)
}

func FromPtr[T any](ptr *T) Value[T] {
	var def T
	if ptr == nil {
		return NewValue(false, def)
	}
	return NewValue(true, *ptr)
}

func (v Value[T]) Equal(other Value[T]) bool {
	return (!v.IsSet && !other.IsSet) || reflect.DeepEqual(v.Value, other.Value)
}

func (v *Value[T]) MarshalJSON() ([]byte, error) {
	if v.IsSet {
		return json.Marshal(v.Value)
	}
	return []byte("null"), nil
}

func (v Value[T]) MarshalYAML() (any, error) {
	if v.IsSet {
		return v.Value, nil
	}
	return nil, nil
}

func (v Value[T]) Ptr() *T {
	if v.IsSet {
		return new(v.Value)
	}
	return nil
}

func (v *Value[T]) UnmarshalJSON(data []byte) error {
	var def T
	if bytes.Equal(data, []byte("null")) {
		v.IsSet = false
		v.Value = def
		return nil
	}
	v.IsSet = true
	return json.Unmarshal(data, &v.Value)
}

func (v *Value[T]) UnmarshalYAML(value *yaml.Node) error {
	var ptr *T
	err := value.Decode(&ptr)
	if err != nil {
		return err
	}
	*v = FromPtr(ptr)
	return nil
}
