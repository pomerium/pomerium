// Package healthv2 reports the health of Pomerium components to sinks.
// Nothing in this package exits the process.
package healthv2

import (
	"context"
)

// ServiceEvaluator must be safe for concurrent use.
// TODO : guidelines.
// See also guidelines for Evaluator.
type ServiceEvaluator interface {
	// Service returns which Pomerium service the health evaluator corresponds to.
	Service() ServiceID
	// Human readable and unique string to identify what this evaluator measures.
	Component() string

	Evaluator
}

// Evaluator is a subset interface of HealthChecker
// used by helper types
type Evaluator interface {
	Initialized(ctx context.Context) (bool, Info)
	Ready(ctx context.Context) (bool, Info)
	Healthy(ctx context.Context) (bool, Info)

	// OnShutdown is only called once.
	OnShutdown(ctx context.Context, shutdownErr error)
}

// TODO : guidelines.
type HealthSink interface {
	Run()
	// Notify must not block. It is called only when the snapshot differs from
	// the previous one.
	Notify(Snapshot)
	// Shutdown takes the shutdown ctx and is meant to be called from
	// context.AfterFunc on it by the code that registers the sink. Notify may
	// still be called afterwards.
	Shutdown(ctx context.Context)
}

type ServiceID string

const (
	ServiceControlPlane ServiceID = "ControlPlane"
	ServiceAuthorize    ServiceID = "Authorize"
	ServiceAuthenticate ServiceID = "Authenticate"
	ServiceProxy        ServiceID = "Proxy"
	ServiceDataBroker   ServiceID = "DataBroker"
	ServiceEnvoy        ServiceID = "Envoy"
)

// Info is reported by v2.Evaluator and consumed by v2.Sink
type Info struct {
	// Reason is the details around the state reported by an Evaluator
	Reason string
	// Details is metadata about the evaluators's current state,
	// This can hold true/false conditions and other metadata.
	// Example {"role": "follower"} for a clustered databroker server
	Details map[string]string
}
