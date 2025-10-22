package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseJSON(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{}`))
		assert.NoError(t, err)
		assert.Len(t, p.Rules, 0)
	})
	t.Run("allow", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{ "allow": {} }`))
		assert.NoError(t, err)
		assert.Len(t, p.Rules, 1)
	})
	t.Run("deny", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{ "deny": {} }`))
		assert.NoError(t, err)
		assert.Len(t, p.Rules, 1)
	})
	t.Run("invalid rule type", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`1`))
		assert.Error(t, err)
		assert.Nil(t, p)
	})
	t.Run("invalid rule action", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{ "some-other-action": {} }`))
		assert.Error(t, err)
		assert.Nil(t, p)
	})
	t.Run("rule array", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`[{ "deny": {} }]`))
		assert.NoError(t, err)
		assert.Len(t, p.Rules, 1)
	})
	t.Run("invalid rule array", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`[{ "some-other-action": {} }]`))
		assert.Error(t, err)
		assert.Nil(t, p)
	})
	t.Run("invalid rule array type", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`[1]`))
		assert.Error(t, err)
		assert.Nil(t, p)
	})
	t.Run("logical operators", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{
          "allow": {
            "and": [],
            "or": [],
            "not": []
          }
        }`))
		assert.NoError(t, err)
		assert.Len(t, p.Rules, 1)
	})
	t.Run("invalid logical operator", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{
          "allow": {
            "iff": []
          }
        }`))
		assert.Error(t, err)
		assert.Nil(t, p)
	})
	t.Run("criteria", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{
		  "allow": {
		    "and": [
		      { "criterion1": 1 },
		      { "criterion2": 2 },
		      { "criterion3/sub": 3 }
		    ]
		  }
		}`))
		assert.NoError(t, err)
		assert.Equal(t, &Policy{
			Rules: []Rule{{
				Action: ActionAllow,
				And: []Criterion{
					{Name: "criterion1", Data: Number("1")},
					{Name: "criterion2", Data: Number("2")},
					{Name: "criterion3", SubPath: "sub", Data: Number("3")},
				},
			}},
		}, p)
	})
	t.Run("empty criteria", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{
		  "allow": {
		    "and": [
		      { }
		    ]
		  }
		}`))
		assert.Error(t, err)
		assert.Nil(t, p)
	})
	t.Run("invalid multiple criteria", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{
		  "allow": {
		    "and": [
		      { "criterion1": 1, "criterion2": 1  }
		    ]
		  }
		}`))
		assert.Error(t, err)
		assert.Nil(t, p)
	})
	t.Run("invalid criteria type", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{
		  "allow": {
		    "and": { "criterion1": 1 }
		  }
		}`))
		assert.Error(t, err)
		assert.Nil(t, p)
	})
	t.Run("invalid criteria array type", func(t *testing.T) {
		p, err := ParseJSON(strings.NewReader(`{
		  "allow": {
		    "and": [1]
		  }
		}`))
		assert.Error(t, err)
		assert.Nil(t, p)
	})
}

func TestParseYAML(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		p, err := ParseYAML(strings.NewReader(`
allow:
  and:
    - criterion1: 1
    - criterion2: 2
    - criterion3/sub: 3
  or:
    - criterion4: 4
deny:
  not:
    - criterion5: 5
`))
		assert.NoError(t, err)
		assert.Equal(t, &Policy{
			Rules: []Rule{
				{
					Action: ActionAllow,
					And: []Criterion{
						{Name: "criterion1", Data: Number("1")},
						{Name: "criterion2", Data: Number("2")},
						{Name: "criterion3", SubPath: "sub", Data: Number("3")},
					},
					Or: []Criterion{
						{Name: "criterion4", Data: Number("4")},
					},
				},
				{
					Action: ActionDeny,
					Not: []Criterion{
						{Name: "criterion5", Data: Number("5")},
					},
				},
			},
		}, p)
	})
}
