package authorize

import (
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/engine"
	// Register the built-in AuthZEN engine. Out-of-tree engines may be
	// added by importing their packages with a blank identifier in a
	// custom Pomerium build.
	_ "github.com/pomerium/pomerium/authorize/evaluator/engine/authzen"
	"github.com/pomerium/pomerium/config"
)

// buildPolicyEngine assembles the PolicyEngine described by opts, using
// inner as the OPA backing evaluator.
//
// The engine kind is looked up in the engine package's registry. The
// per-engine configuration is passed through opaquely as opts.ExternalPolicyEngine.
func buildPolicyEngine(opts *config.Options, inner *evaluator.Evaluator) (engine.PolicyEngine, error) {
	return engine.Build(engine.Kind(opts.PolicyEngine), engine.FactoryConfig{
		EngineConfig:           opts.ExternalPolicyEngine,
		OPAInner:               inner,
		ExternalEnginesEnabled: opts.IsRuntimeFlagSet(config.RuntimeFlagExternalPolicyEngine),
	})
}
