package parser

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/cespare/xxhash/v2"
)

// A Policy is a policy made up of multiple allow or deny rules.
type Policy struct {
	Rules []Rule
}

// MarshalJSON marshals the policy as JSON.
func (p *Policy) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToJSON())
}

// String converts the policy to a string.
func (p *Policy) String() string {
	str, _ := p.MarshalJSON()
	return string(str)
}

// ToJSON converts the policy to JSON.
func (p *Policy) ToJSON() Value {
	var root Array

	for _, r := range p.Rules {
		root = append(root, r.ToJSON())
	}

	return root
}

// Hash returns a hash of the policy.
func (p *Policy) Hash() uint64 {
	h := xxhash.New()
	_, _ = p.ToJSON().WriteJSON(h)
	return h.Sum64()
}

// PolicyFromValue converts a value into a Policy.
func PolicyFromValue(v Value) (*Policy, error) {
	rules, err := RulesFromValue(v)
	if err != nil {
		return nil, fmt.Errorf("invalid rules in policy: %w", err)
	}
	return &Policy{
		Rules: rules,
	}, nil
}

// A Rule is a policy rule with a corresponding action ("allow" or "deny"),
// and conditionals to determine if the rule matches or not.
type Rule struct {
	Action Action
	And    []Criterion
	Or     []Criterion
	Not    []Criterion
	Nor    []Criterion
}

// RulesFromValue converts a Value into a slice of Rules. Only Arrays or Objects
// are supported.
func RulesFromValue(v Value) ([]Rule, error) {
	switch t := v.(type) {
	case Array:
		return RulesFromArray(t)
	case Object:
		return RulesFromObject(t)
	default:
		return nil, fmt.Errorf("unsupported type for rule: %T", v)
	}
}

// RulesFromArray converts an Array into a slice of Rules. Each element of the Array is
// converted using RulesFromObject and merged together.
func RulesFromArray(a Array) ([]Rule, error) {
	var rules []Rule
	for _, v := range a {
		switch t := v.(type) {
		case Object:
			inner, err := RulesFromObject(t)
			if err != nil {
				return nil, err
			}
			rules = append(rules, inner...)
		default:
			return nil, fmt.Errorf("unsupported type for rules array: %T", v)
		}
	}
	return rules, nil
}

// RulesFromObject converts an Object into a slice of Rules.
//
// One form is supported:
//
//  1. An object where the keys are the actions and the values are an object with "and", "or", or "not" fields:
//     `{ "allow": { "and": [ {"groups": "group1"} ] } }`
func RulesFromObject(o Object) ([]Rule, error) {
	var rules []Rule
	for k, v := range o {
		action, err := ActionFromValue(String(k))
		if err != nil {
			return nil, fmt.Errorf("invalid action in rule: %w", err)
		}

		oo, ok := v.(Object)
		if !ok {
			return nil, fmt.Errorf("invalid value for action in rule, expected Object, got %T", v)
		}

		rule := Rule{
			Action: action,
		}
		err = rule.fillConditionalsFromObject(oo)
		if err != nil {
			return nil, err
		}

		rules = append(rules, rule)
	}
	// sort by action for deterministic ordering
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Action < rules[j].Action
	})
	return rules, nil
}

// MarshalJSON marshals the rule as JSON.
func (r *Rule) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.ToJSON())
}

// String converts the rule to a string.
func (r *Rule) String() string {
	str, _ := r.MarshalJSON()
	return string(str)
}

// ToJSON converts the rule to JSON.
func (r *Rule) ToJSON() Value {
	body := Object{}

	for _, op := range []struct {
		operator string
		criteria []Criterion
	}{
		{"and", r.And},
		{"or", r.Or},
		{"not", r.Not},
		{"nor", r.Nor},
	} {
		if len(op.criteria) == 0 {
			continue
		}

		var criteria Array
		for _, c := range op.criteria {
			criteria = append(criteria, c.ToJSON())
		}

		body[op.operator] = criteria
	}

	return Object{
		string(r.Action): body,
	}
}

func (r *Rule) fillConditionalsFromObject(o Object) error {
	conditionals := []struct {
		Name     string
		Criteria *[]Criterion
	}{
		{"and", &r.And},
		{"or", &r.Or},
		{"not", &r.Not},
		{"nor", &r.Nor},
	}
	for _, cond := range conditionals {
		if rawCriteria, ok := o[cond.Name]; ok {
			criteria, err := CriteriaFromValue(rawCriteria)
			if err != nil {
				return fmt.Errorf("invalid criteria in \"%s\"): %w", cond.Name, err)
			}
			*cond.Criteria = criteria
		}
	}
	for k := range o {
		switch k {
		case "and", "or", "not", "nor", "action":
		default:
			return fmt.Errorf("unsupported conditional \"%s\", only and, or, not, nor and action are allowed", k)
		}
	}
	return nil
}

// A Criterion is used by a rule to determine if the rule matches or not.
//
// Criteria RegoRulesGenerators are registered based on the specified name.
// Data is arbitrary JSON data sent to the generator.
type Criterion struct {
	Name    string
	SubPath string
	Data    Value
}

// CriteriaFromValue converts a Value into Criteria. Only Arrays are supported.
func CriteriaFromValue(v Value) ([]Criterion, error) {
	switch t := v.(type) {
	case Array:
		return CriteriaFromArray(t)
	default:
		return nil, fmt.Errorf("unsupported type for criteria: %T", v)
	}
}

// CriteriaFromArray converts an Array into Criteria. Each element of the Array is
// converted using CriterionFromObject.
func CriteriaFromArray(a Array) ([]Criterion, error) {
	var criteria []Criterion
	for _, v := range a {
		switch t := v.(type) {
		case Object:
			inner, err := CriterionFromObject(t)
			if err != nil {
				return nil, err
			}
			criteria = append(criteria, *inner)
		default:
			return nil, fmt.Errorf("unsupported type for criteria array: %T", v)
		}
	}
	return criteria, nil
}

// CriterionFromObject converts an Object into a Criterion.
//
// One form is supported:
//
//  1. An object where the keys are the names with a sub path and the values are the corresponding
//     data for each Criterion: `{ "groups": "group1" }`
func CriterionFromObject(o Object) (*Criterion, error) {
	if len(o) != 1 {
		return nil, fmt.Errorf("each criteria may only contain a single key and value")
	}

	for k, v := range o {
		name := k
		subPath := ""
		if idx := strings.Index(k, "/"); idx >= 0 {
			name, subPath = k[:idx], k[idx+1:]
		}
		return &Criterion{
			Name:    name,
			SubPath: subPath,
			Data:    v,
		}, nil
	}

	// this can't happen
	panic("each criteria may only contain a single key and value")
}

// MarshalJSON marshals the criterion as JSON.
func (c *Criterion) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.ToJSON())
}

// String converts the criterion to a string.
func (c *Criterion) String() string {
	str, _ := c.MarshalJSON()
	return string(str)
}

// ToJSON converts the criterion to JSON.
func (c *Criterion) ToJSON() Value {
	nm := c.Name
	if c.SubPath != "" {
		nm += "/" + c.SubPath
	}
	return Object{nm: c.Data}
}

// An Action describe what to do when a rule matches, either "allow" or "deny".
type Action string

// ActionFromValue converts a Value into an Action.
func ActionFromValue(value Value) (Action, error) {
	s, ok := value.(String)
	if !ok {
		return "", fmt.Errorf("unsupported type for action: %T", value)
	}
	switch Action(s) {
	case ActionAllow:
		return ActionAllow, nil
	case ActionDeny:
		return ActionDeny, nil
	}

	return "", fmt.Errorf("unsupported action: %s", s)
}

// Actions
const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)
