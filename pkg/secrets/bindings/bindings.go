// Package bindings models the secret binding table: the pairing of a stable ID
// with a backend Ref and per-secret tuning, organized into hierarchical scopes
// with leaf-wins shadowing.
//
// OSS uses only the implicit root scope, but the hierarchical walk is built and
// tested now because Enterprise namespaces sit on top of it unchanged.
package bindings

import (
	"fmt"
	"regexp"
	"time"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// Canonical tuning defaults and the refresh floor.
const (
	DefaultRefresh     = 5 * time.Minute
	DefaultStaleGrace  = 30 * time.Minute
	DefaultNegativeTTL = 30 * time.Second
	MinRefresh         = time.Second
)

// IDPattern is the binding-ID charset. It must stay renderable as ${secret.ID}:
// no dots (ambiguous in ${secret.a.b}) and a leading char that is not '-'. The
// header-template grammar is laxer than this, so this is the only real gate.
var IDPattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_-]*$`)

// Binding pairs a stable ID with a backend Ref and per-secret tuning.
type Binding struct {
	ID          string
	Ref         ref.Ref
	Refresh     time.Duration
	StaleGrace  time.Duration
	NegativeTTL time.Duration
	MetricLabel string
}

// Defaults are the tuning values applied to bindings that leave a field unset.
type Defaults struct {
	Refresh     time.Duration
	StaleGrace  time.Duration
	NegativeTTL time.Duration
}

// Scope is one level of the binding table, optionally shadowing a parent.
type Scope struct {
	parent *Scope
	byID   map[string]Binding
}

// NewScope validates bs, applies d to unset fields, and returns a scope
// shadowing parent. Validation covers: ID charset, duplicate IDs within this
// level, non-negative tuning, the refresh floor (after defaults), and
// registry acceptance of each ref. Error messages name the offending binding
// ID (config, never secret material).
func NewScope(parent *Scope, bs []Binding, d Defaults, reg *provider.Registry) (*Scope, error) {
	byID := make(map[string]Binding, len(bs))
	for _, b := range bs {
		if !IDPattern.MatchString(b.ID) {
			return nil, fmt.Errorf("secret binding %q: invalid ID, must match %s", b.ID, IDPattern.String())
		}
		if _, dup := byID[b.ID]; dup {
			return nil, fmt.Errorf("secret binding %q: duplicate ID within scope", b.ID)
		}
		if b.Refresh < 0 {
			return nil, fmt.Errorf("secret binding %q: refresh must not be negative", b.ID)
		}
		if b.StaleGrace < 0 {
			return nil, fmt.Errorf("secret binding %q: stale_grace must not be negative", b.ID)
		}
		if b.NegativeTTL < 0 {
			return nil, fmt.Errorf("secret binding %q: negative_ttl must not be negative", b.ID)
		}

		if b.Refresh == 0 {
			b.Refresh = d.Refresh
		}
		if b.StaleGrace == 0 {
			b.StaleGrace = d.StaleGrace
		}
		if b.NegativeTTL == 0 {
			b.NegativeTTL = d.NegativeTTL
		}
		if b.MetricLabel == "" {
			b.MetricLabel = b.ID
		}

		if b.Refresh < MinRefresh {
			return nil, fmt.Errorf("secret binding %q: refresh %s below minimum %s", b.ID, b.Refresh, MinRefresh)
		}
		if err := reg.Validate(b.Ref); err != nil {
			return nil, fmt.Errorf("secret binding %q: %w", b.ID, err)
		}

		byID[b.ID] = b
	}
	return &Scope{parent: parent, byID: byID}, nil
}

// Resolve looks up id, walking from this scope up through parents (leaf wins).
func (s *Scope) Resolve(id string) (Binding, bool) {
	for cur := s; cur != nil; cur = cur.parent {
		if b, ok := cur.byID[id]; ok {
			return b, true
		}
	}
	return Binding{}, false
}
