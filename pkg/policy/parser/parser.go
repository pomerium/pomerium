// Package parser contains a parser for Pomerium Policy Language.
//
// The Pomerium Policy Language is a JSON or YAML document containing rules,
// actions, logical operators and criteria.
//
// The document contains zero or more rules.
//
// A rule has an action and zero or more logical operators.
//
// An action is either "allow" or "deny".
//
// The logical operators are "and", "or" and "not" and contain zero or more criteria.
//
// A criterion has a name and arbitrary JSON data.
//
// An example policy:
//
//	allow:
//	  and:
//	  - domain: example.com
//	  - group: admin
//	deny:
//	  or:
//	  - user: user1@example.com
//	  - user: user2@example.com
//
// The JSON Schema for the language:
//
//	{
//	  "$ref": "#/definitions/policy",
//	  "definitions": {
//	    "policy": {
//	      "anyOf": [
//	        { "$ref": "#/definitions/rules" },
//	        {
//	          "type": "array",
//	          "items": { "$ref": "#/definitions/rules" }
//	        }
//	      ]
//	    },
//	    "rules": {
//	      "type": "object",
//	      "properties": {
//	        "allow": { "$ref": "#/definitions/rule_body" },
//	        "deny": { "$ref": "#/definitions/rule_body" }
//	      }
//	    },
//	    "rule_body": {
//	      "type": "object",
//	      "properties": {
//	        "and": {
//	          "type": "array",
//	          "items": { "$ref": "#/definitions/criteria" }
//	        },
//	        "not": {
//	          "type": "array",
//	          "items": { "$ref": "#/definitions/criteria" }
//	        },
//	        "or": {
//	          "type": "array",
//	          "items": { "$ref": "#/definitions/criteria" }
//	        }
//	      },
//	      "additionalProperties": false
//	    },
//	    "criteria": {
//	      "type": "object",
//	      "additionalProperties": true,
//	      "minProperties": 1,
//	      "maxProperties": 1
//	    }
//	  }
//	}
package parser

import (
	"bytes"
	"encoding/json"
	"io"

	"gopkg.in/yaml.v3"
)

// A Parser parses raw policy definitions into a Policy.
type Parser struct{}

// New creates a new Parser.
func New() *Parser {
	p := &Parser{}
	return p
}

// ParseJSON parses a raw JSON document into a policy.
func (p *Parser) ParseJSON(r io.Reader) (*Policy, error) {
	doc, err := ParseValue(r)
	if err != nil {
		return nil, err
	}
	return PolicyFromValue(doc)
}

// ParseYAML parses a raw YAML document into a policy.
func (p *Parser) ParseYAML(r io.Reader) (*Policy, error) {
	var obj any
	err := yaml.NewDecoder(r).Decode(&obj)
	if err != nil {
		return nil, err
	}
	bs, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return p.ParseJSON(bytes.NewReader(bs))
}

// ParseJSON creates a parser and calls ParseJSON on it.
func ParseJSON(r io.Reader) (*Policy, error) {
	return New().ParseJSON(r)
}

// ParseYAML creates a parser and calls ParseYAML on it.
func ParseYAML(r io.Reader) (*Policy, error) {
	return New().ParseYAML(r)
}
