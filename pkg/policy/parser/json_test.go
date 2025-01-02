package parser

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
)

func TestArray(t *testing.T) {
	var _ Value = Array{}
	t.Run("Clone", func(t *testing.T) {
		a1 := Array{Number("1"), Number("2"), Number("3")}
		a2 := a1.Clone()
		assert.Equal(t, a1, a2)
	})
	t.Run("RegoValue", func(t *testing.T) {
		a := Array{Number("1"), Number("2")}
		assert.Equal(t, ast.NewArray(
			ast.NumberTerm("1"),
			ast.NumberTerm("2"),
		), a.RegoValue())
	})
	t.Run("String", func(t *testing.T) {
		a := Array{Number("1"), Number("2"), Boolean(true)}
		assert.Equal(t, `[1,2,true]`, a.String())
	})
}

func TestBoolean(t *testing.T) {
	var _ Value = Boolean(true)
	t.Run("Clone", func(t *testing.T) {
		b1 := Boolean(true)
		b2 := b1.Clone()
		assert.Equal(t, b1, b2)
	})
	t.Run("RegoValue", func(t *testing.T) {
		b := Boolean(true)
		assert.Equal(t, ast.Boolean(true), b.RegoValue())
	})
	t.Run("String", func(t *testing.T) {
		b := Boolean(true)
		assert.Equal(t, `true`, b.String())
	})
}

func TestNull(t *testing.T) {
	var _ Value = Null{}
	t.Run("Clone", func(t *testing.T) {
		n1 := Null{}
		n2 := n1.Clone()
		assert.Equal(t, n1, n2)
	})
	t.Run("RegoValue", func(t *testing.T) {
		n := Null{}
		assert.Equal(t, ast.Null{}, n.RegoValue())
	})
	t.Run("String", func(t *testing.T) {
		n := Null{}
		assert.Equal(t, `null`, n.String())
	})
}

func TestNumber(t *testing.T) {
	var _ Value = Number("1")
	t.Run("Clone", func(t *testing.T) {
		n1 := Number("1")
		n2 := n1.Clone()
		assert.Equal(t, n1, n2)
	})
	t.Run("RegoValue", func(t *testing.T) {
		n := Number("1")
		assert.Equal(t, ast.Number("1"), n.RegoValue())
	})
	t.Run("String", func(t *testing.T) {
		n := Number("1")
		assert.Equal(t, `1`, n.String())
	})
}

func TestObject(t *testing.T) {
	var _ Value = Object{}
	t.Run("Clone", func(t *testing.T) {
		o1 := Object{"x": String("y")}
		o2 := o1.Clone().(Object)
		assert.Equal(t, o1, o2)
		o2["x"] = String("z")
		assert.NotEqual(t, o1, o2)
	})
	t.Run("RegoValue", func(t *testing.T) {
		o := Object{"x": String("y")}
		assert.Equal(t, ast.NewObject(
			[2]*ast.Term{ast.StringTerm("x"), ast.StringTerm("y")},
		), o.RegoValue())
	})
	t.Run("String", func(t *testing.T) {
		o1 := Object{"x": String("y")}
		assert.Equal(t, `{"x":"y"}`, o1.String())
	})
}

func TestString(t *testing.T) {
	var _ Value = String("test")
	t.Run("Clone", func(t *testing.T) {
		s1 := String("test")
		s2 := s1.Clone()
		assert.Equal(t, s1, s2)
	})
	t.Run("RegoValue", func(t *testing.T) {
		s := String("test")
		assert.Equal(t, ast.String("test"), s.RegoValue())
	})
	t.Run("String", func(t *testing.T) {
		s := String("test")
		assert.Equal(t, `"test"`, s.String())
	})
}
