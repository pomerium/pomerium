package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/mitchellh/mapstructure"
)

// A StringSlice is a slice of strings.
type StringSlice []string

// NewStringSlice creatse a new StringSlice.
func NewStringSlice(values ...string) StringSlice {
	return StringSlice(values)
}

const (
	array = iota
	arrayValue
	object
	objectKey
	objectValue
)

// UnmarshalJSON unmarshals a JSON document into the string slice.
func (slc *StringSlice) UnmarshalJSON(data []byte) error {
	typeStack := []int{array}
	stateStack := []int{arrayValue}

	var vals []string
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		token, err := dec.Token()
		if err != nil {
			break
		}

		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '[':
				typeStack = append(typeStack, array)
				stateStack = append(stateStack, arrayValue)
			case '{':
				typeStack = append(typeStack, object)
				stateStack = append(stateStack, objectKey)
			case ']', '}':
				typeStack = typeStack[:len(typeStack)-1]
				stateStack = stateStack[:len(stateStack)-1]
			}
			continue
		}

		switch stateStack[len(stateStack)-1] {
		case objectKey:
			stateStack[len(stateStack)-1] = objectValue
		case objectValue:
			stateStack[len(stateStack)-1] = objectKey
			fallthrough
		default:
			switch t := token.(type) {
			case bool:
				vals = append(vals, fmt.Sprint(t))
			case float64:
				vals = append(vals, fmt.Sprint(t))
			case json.Number:
				vals = append(vals, fmt.Sprint(t))
			case string:
				vals = append(vals, t)
			default:
			}
		}
	}
	*slc = StringSlice(vals)
	return nil
}

// UnmarshalYAML unmarshals a YAML document into the string slice. UnmarshalJSON is
// reused as the actual implementation.
func (slc *StringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var i interface{}
	err := unmarshal(&i)
	if err != nil {
		return err
	}
	bs, err := json.Marshal(i)
	if err != nil {
		return err
	}
	return slc.UnmarshalJSON(bs)
}

// DecodeOptionsHookFunc returns a decode hook that will attempt to convert any type to a StringSlice.
func DecodeOptionsHookFunc() mapstructure.DecodeHookFunc {
	return func(f, t reflect.Type, data interface{}) (interface{}, error) {
		if t != reflect.TypeOf(Options{}) {
			return data, nil
		}

		m, ok := data.(map[string]interface{})
		if !ok {
			return data, nil
		}

		ps, ok := m["policy"].([]interface{})
		if !ok {
			return data, nil
		}

		for _, p := range ps {
			pm, ok := p.(map[interface{}]interface{})
			if !ok {
				continue
			}
			rawTo, ok := pm["to"]
			if !ok {
				continue
			}
			rawBS, err := json.Marshal(rawTo)
			if err != nil {
				return nil, err
			}
			var slc StringSlice
			err = json.Unmarshal(rawBS, &slc)
			if err != nil {
				return nil, err
			}
			pm["to"] = slc
		}

		return data, nil
	}
}
