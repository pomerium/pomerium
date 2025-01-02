package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/open-policy-agent/opa/v1/ast"
)

// A Value is a JSON value. Either an object, array, string, number, boolean or null.
type Value interface {
	isValue()
	Clone() Value
	RegoValue() ast.Value
}

// ParseValue parses JSON into a value.
func ParseValue(r io.Reader) (Value, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()

	tok, err := dec.Token()
	if errors.Is(err, io.EOF) {
		return nil, io.ErrUnexpectedEOF
	} else if err != nil {
		return nil, err
	}

	v, err := parseValue(dec, tok)
	if err != nil {
		return v, err
	}
	if dec.More() {
		return nil, fmt.Errorf("unexpected additional json value: offset=%d", dec.InputOffset())
	}
	return v, nil
}

func parseValue(dec *json.Decoder, tok json.Token) (Value, error) {
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '[':
			return parseArray(dec)
		case '{':
			return parseObject(dec)
		default:
			return nil, fmt.Errorf("unsupported json delimiter: %s", string(d))
		}
	}

	return parseSimple(tok)
}

func parseArray(dec *json.Decoder) (Value, error) {
	var a Array
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		} else if err != nil {
			return nil, err
		}

		if d, ok := tok.(json.Delim); ok && d == ']' {
			return a, nil
		}

		v, err := parseValue(dec, tok)
		if err != nil {
			return nil, err
		}
		a = append(a, v)
	}
}

func parseObject(dec *json.Decoder) (Value, error) {
	o := make(Object)
	k := ""
	for i := 0; ; i++ {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		} else if err != nil {
			return nil, err
		}

		if d, ok := tok.(json.Delim); ok && d == '}' {
			return o, nil
		}

		v, err := parseValue(dec, tok)
		if err != nil {
			return nil, err
		}

		// if we're handling a key
		if i%2 == 0 {
			s, ok := v.(String)
			if !ok {
				return nil, fmt.Errorf("unsupported object key type: %T", v)
			}
			k = string(s)
		} else {
			o[k] = v
		}
	}
}

func parseSimple(tok json.Token) (Value, error) {
	switch t := tok.(type) {
	case bool:
		return Boolean(t), nil
	case json.Number:
		return Number(t), nil
	case string:
		return String(t), nil
	case nil:
		return Null{}, nil
	}

	return nil, fmt.Errorf("unsupported json token type: %T", tok)
}

// An Object is a map of strings to values.
type Object map[string]Value

func (Object) isValue() {}

// Clone clones the Object.
func (o Object) Clone() Value {
	no := make(Object)
	for k, v := range o {
		no[k] = v
	}
	return no
}

// Falsy returns true if the value is considered Javascript falsy:
//
//	https://developer.mozilla.org/en-US/docs/Glossary/Falsy.
//
// If the field is not found in the object it is *not* falsy.
func (o Object) Falsy(field string) bool {
	v, ok := o[field]
	if !ok {
		return false
	}

	switch v := v.(type) {
	case Boolean:
		return !bool(v)
	case Number:
		return v.Float64() == 0 || math.IsNaN(v.Float64())
	case String:
		return v == ""
	case Null:
		return true
	default:
		return false
	}
}

// RegoValue returns the Object as a rego Value.
func (o Object) RegoValue() ast.Value {
	kvps := make([][2]*ast.Term, 0, len(o))
	for k, v := range o {
		if v == nil {
			v = Null{}
		}
		kvps = append(kvps, [2]*ast.Term{
			ast.StringTerm(k),
			ast.NewTerm(v.RegoValue()),
		})
	}
	return ast.NewObject(kvps...)
}

// String returns the JSON representation of the Object.
func (o Object) String() string {
	bs, _ := json.Marshal(o)
	return string(bs)
}

// Truthy returns the opposite of Falsy, however if the field is not found in the object it is neither truthy nor falsy.
func (o Object) Truthy(field string) bool {
	_, ok := o[field]
	if !ok {
		return false
	}

	return !o.Falsy(field)
}

// An Array is a slice of values.
type Array []Value

func (Array) isValue() {}

// Clone clones the array.
func (a Array) Clone() Value {
	na := make(Array, len(a))
	copy(na, a)
	return na
}

// RegoValue returns the Array as a rego Value.
func (a Array) RegoValue() ast.Value {
	var vs []*ast.Term
	for _, v := range a {
		vs = append(vs, ast.NewTerm(v.RegoValue()))
	}
	return ast.NewArray(vs...)
}

// String returns the JSON representation of the Array.
func (a Array) String() string {
	bs, _ := json.Marshal(a)
	return string(bs)
}

// A String is a wrapper around a string.
type String string

func (String) isValue() {}

// Clone clones the string.
func (s String) Clone() Value {
	return s
}

// RegoValue returns the String as a rego Value.
func (s String) RegoValue() ast.Value {
	return ast.String(s)
}

// String returns the JSON representation of the String.
func (s String) String() string {
	bs, _ := json.Marshal(s)
	return string(bs)
}

// A Number is an integer or a floating point value stored in string representation.
type Number string

func (Number) isValue() {}

// Clone clones the number.
func (n Number) Clone() Value {
	return n
}

// Float64 returns the number as a float64.
func (n Number) Float64() float64 {
	v, _ := json.Number(n).Float64()
	return v
}

// Int64 returns the number as an int64.
func (n Number) Int64() int64 {
	v, _ := json.Number(n).Int64()
	return v
}

// RegoValue returns the Number as a rego Value.
func (n Number) RegoValue() ast.Value {
	return ast.Number(n)
}

// String returns the JSON representation of the Number.
func (n Number) String() string {
	return string(n)
}

// MarshalJSON marshals the number as JSON.
func (n Number) MarshalJSON() ([]byte, error) {
	return []byte(n), nil
}

// A Boolean is either true or false.
type Boolean bool

func (Boolean) isValue() {}

// Clone clones the boolean.
func (b Boolean) Clone() Value {
	return b
}

// RegoValue returns the Boolean as a rego Value.
func (b Boolean) RegoValue() ast.Value {
	return ast.Boolean(b)
}

// String returns the JSON representation of the Boolean.
func (b Boolean) String() string {
	if b {
		return "true"
	}
	return "false"
}

// A Null is the nil value.
type Null struct{}

func (Null) isValue() {}

// Clone clones the null.
func (Null) Clone() Value {
	return Null{}
}

// RegoValue returns the Null as a rego Value.
func (Null) RegoValue() ast.Value {
	return ast.Null{}
}

// String returns JSON null.
func (Null) String() string {
	return "null"
}
