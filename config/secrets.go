package config

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/internal/headertemplate"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/secrets"
	"github.com/pomerium/pomerium/pkg/secrets/bindings"
	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// ReferenceableFields is the single list of proto fields whose values may carry
// ${secret.ID} references. M7's lint test diffs it against the (referenceable)
// proto annotations; extend it (and the annotation) together when a field
// becomes referenceable in a later phase.
var ReferenceableFields = []string{"pomerium.config.Route.set_request_headers"}

// SecretsOptions is the YAML/settings `secrets` block: a binding table plus
// tuning defaults. Its fields are operator config, never secret material.
type SecretsOptions struct {
	Defaults SecretsDefaultsOptions           `mapstructure:"defaults" yaml:"defaults,omitempty"`
	Bindings map[string]SecretsBindingOptions `mapstructure:"bindings" yaml:"bindings,omitempty"`
}

// SecretsDefaultsOptions are the tuning defaults applied to bindings that leave
// a field unset.
type SecretsDefaultsOptions struct {
	Refresh     time.Duration `mapstructure:"refresh" yaml:"refresh,omitempty"`
	StaleGrace  time.Duration `mapstructure:"stale_grace" yaml:"stale_grace,omitempty"`
	NegativeTTL time.Duration `mapstructure:"negative_ttl" yaml:"negative_ttl,omitempty"`
}

// SecretsBindingOptions is one entry of the binding table (map key = ID).
type SecretsBindingOptions struct {
	URL        string        `mapstructure:"url" yaml:"url"`
	Refresh    time.Duration `mapstructure:"refresh" yaml:"refresh,omitempty"`
	StaleGrace time.Duration `mapstructure:"stale_grace" yaml:"stale_grace,omitempty"`
}

// resolveDefaults merges the configured defaults over the canonical defaults.
func (o *SecretsOptions) resolveDefaults() bindings.Defaults {
	d := bindings.Defaults{
		Refresh:     bindings.DefaultRefresh,
		StaleGrace:  bindings.DefaultStaleGrace,
		NegativeTTL: bindings.DefaultNegativeTTL,
	}
	if o.Defaults.Refresh > 0 {
		d.Refresh = o.Defaults.Refresh
	}
	if o.Defaults.StaleGrace > 0 {
		d.StaleGrace = o.Defaults.StaleGrace
	}
	if o.Defaults.NegativeTTL > 0 {
		d.NegativeTTL = o.Defaults.NegativeTTL
	}
	return d
}

// ToScope parses and validates the binding table into a resolver scope. It is
// the single validating conversion used by both config validation and the
// authorize runtime.
func (o *SecretsOptions) ToScope(reg *provider.Registry) (*bindings.Scope, bindings.Defaults, error) {
	d := o.resolveDefaults()
	bs := make([]bindings.Binding, 0, len(o.Bindings))
	for id, b := range o.Bindings {
		r, err := ref.Parse(b.URL)
		if err != nil {
			return nil, d, fmt.Errorf("secret binding %q: %w", id, err)
		}
		bs = append(bs, bindings.Binding{
			ID:         id,
			Ref:        r,
			Refresh:    b.Refresh,
			StaleGrace: b.StaleGrace,
		})
	}
	scope, err := bindings.NewScope(nil, bs, d, reg)
	if err != nil {
		return nil, d, err
	}
	return scope, d, nil
}

// Validate checks the binding table against the provider registry.
func (o *SecretsOptions) Validate(reg *provider.Registry) error {
	_, _, err := o.ToScope(reg)
	return err
}

// isZero reports whether the block carries nothing (no defaults, no bindings),
// so absence round-trips as a nil proto message.
func (o *SecretsOptions) isZero() bool {
	return len(o.Bindings) == 0 && o.Defaults == (SecretsDefaultsOptions{})
}

// applySettingsProto populates o from a proto SecretsSettings. A nil message
// is a no-op (overlay semantics, matching the other settings blocks).
func (o *SecretsOptions) applySettingsProto(p *configpb.SecretsSettings) {
	if p == nil {
		return
	}
	var out SecretsOptions
	if d := p.GetDefaults(); d != nil {
		out.Defaults = SecretsDefaultsOptions{
			Refresh:     durationFromProto(d.GetRefresh()),
			StaleGrace:  durationFromProto(d.GetStaleGrace()),
			NegativeTTL: durationFromProto(d.GetNegativeTtl()),
		}
	}
	if len(p.GetBindings()) > 0 {
		out.Bindings = make(map[string]SecretsBindingOptions, len(p.GetBindings()))
		for id, b := range p.GetBindings() {
			out.Bindings[id] = SecretsBindingOptions{
				URL:        b.GetUrl(),
				Refresh:    durationFromProto(b.GetRefresh()),
				StaleGrace: durationFromProto(b.GetStaleGrace()),
			}
		}
	}
	*o = out
}

// ToProto renders o as a proto SecretsSettings, or nil when empty.
func (o *SecretsOptions) ToProto() *configpb.SecretsSettings {
	if o == nil || o.isZero() {
		return nil
	}
	p := &configpb.SecretsSettings{}
	if o.Defaults != (SecretsDefaultsOptions{}) {
		p.Defaults = &configpb.SecretsDefaults{
			Refresh:     durationToProto(o.Defaults.Refresh),
			StaleGrace:  durationToProto(o.Defaults.StaleGrace),
			NegativeTtl: durationToProto(o.Defaults.NegativeTTL),
		}
	}
	if len(o.Bindings) > 0 {
		p.Bindings = make(map[string]*configpb.SecretsBinding, len(o.Bindings))
		for id, b := range o.Bindings {
			p.Bindings[id] = &configpb.SecretsBinding{
				Url:        b.URL,
				Refresh:    durationToProto(b.Refresh),
				StaleGrace: durationToProto(b.StaleGrace),
			}
		}
	}
	return p
}

func durationFromProto(d *durationpb.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return d.AsDuration()
}

func durationToProto(d time.Duration) *durationpb.Duration {
	if d == 0 {
		return nil
	}
	return durationpb.New(d)
}

// validateSecrets validates the binding table and every route's header values
// against the binding scope. Secret refs are permitted only in per-route
// set_request_headers (ReferenceableFields); response-header surfaces reject
// them in v1.
func (o *Options) validateSecrets() error {
	reg := secrets.DefaultRegistry()
	scope, _, err := o.Secrets.ToScope(reg)
	if err != nil {
		return err
	}
	hasBindings := len(o.Secrets.Bindings) > 0

	var referenced []string
	seen := map[string]struct{}{}

	checkRequestValue := func(where, value string) error {
		if secretResidue(value) {
			return fmt.Errorf("%s: malformed secret reference", where)
		}
		for _, r := range headertemplate.References(value) {
			if len(r) == 0 || r[0] != "secret" {
				continue
			}
			if len(r) != 2 {
				return fmt.Errorf("%s: secret refs take exactly one ID segment", where)
			}
			id := r[1]
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				referenced = append(referenced, id)
			}
			if hasBindings {
				if _, ok := scope.Resolve(id); !ok {
					return fmt.Errorf("%s: unknown secret %q", where, id)
				}
			}
		}
		return nil
	}

	// Iterate policies (and their headers) in a deterministic order.
	for policy := range o.GetAllPolicies() {
		route := policy.String()
		for _, name := range sortedKeys(policy.SetRequestHeaders) {
			if err := checkRequestValue(fmt.Sprintf("route %s request header %q", route, name), policy.SetRequestHeaders[name]); err != nil {
				return err
			}
		}
		for _, name := range sortedKeys(policy.SetResponseHeaders) {
			if secretRefPresent(policy.SetResponseHeaders[name]) {
				return fmt.Errorf("route %s response header %q: secret refs are not supported in response headers in v1", route, name)
			}
		}
	}
	for _, name := range sortedKeys(o.SetResponseHeaders) {
		if secretRefPresent(o.SetResponseHeaders[name]) {
			return fmt.Errorf("response header %q: secret refs are not supported in response headers in v1", name)
		}
	}

	if !hasBindings && len(referenced) > 0 {
		slices.Sort(referenced)
		return fmt.Errorf("routes reference secrets %v but no secrets bindings are configured", referenced)
	}
	return nil
}

// secretResidue reports whether, after substituting every parsed reference with
// empty text, a "${secret" or "$secret" marker survives — the robust signal for
// a malformed secret reference (e.g. dynamic selection via nesting) that the
// parser rolled back to literal text.
func secretResidue(value string) bool {
	out := headertemplate.Render(value, func([]string) string { return "" })
	return strings.Contains(out, "${secret") || strings.Contains(out, "$secret")
}

// secretRefPresent reports whether value contains any parsed secret reference or
// residual secret marker. Used to reject secret refs in response headers.
func secretRefPresent(value string) bool {
	if secretResidue(value) {
		return true
	}
	for _, r := range headertemplate.References(value) {
		if len(r) > 0 && r[0] == "secret" {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
