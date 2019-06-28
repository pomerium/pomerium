package metrics

import (
	"github.com/pomerium/pomerium/internal/log"
	"go.opencensus.io/stats/view"
)

// RegisterHTTPClientView registers the standard HTTPClient view.
// It must be called to see metrics in the configured exporters
func RegisterHTTPClientView() {
	if err := view.Register(HTTPClientRequestCountView, HTTPClientRequestDurationView, HTTPClientRequestSizeView); err != nil {
		log.Warn().Err(err).Msg("Could not register HTTPClientView")
	}
}

// RegisterHTTPServerView registers the standard HTTPServer view.
// It must be called to see metrics in the configured exporters
func RegisterHTTPServerView() {
	if err := view.Register(HTTPServerRequestCountView, HTTPServerRequestDurationView, HTTPServerRequestSizeView); err != nil {
		log.Warn().Err(err).Msg("Could not register HTTPServerView")
	}
}

// RegisterGRPCClientView registers the standard GRPCClient view.
// It must be called to see metrics in the configured exporters
func RegisterGRPCClientView() {
	if err := view.Register(GRPCClientRequestCountView, GRPCClientRequestDurationView, GRPCClientResponseSizeView); err != nil {
		log.Warn().Err(err).Msg("Could not register GRPCClientView")
	}
}
