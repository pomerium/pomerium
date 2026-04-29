package httputil

import "github.com/pomerium/pomerium/pkg/logfields"

// CanonicalHeaderKey re-exports the log.CanonicalHeaderKey function to avoid an import cycle.
var CanonicalHeaderKey = logfields.CanonicalHeaderKey
