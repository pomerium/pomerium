package httputil

import (
	"github.com/pomerium/pomerium/internal/log"
)

// CanonicalHeaderKey re-exports the log.CanonicalHeaderKey function to avoid an import cycle.
var CanonicalHeaderKey = log.CanonicalHeaderKey
