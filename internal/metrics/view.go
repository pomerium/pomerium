package metrics

import (
	"go.opencensus.io/stats/view"
)

// RegisterHTTPClientView registers the standard HTTPClient view.
// It must be called to see metrics in the configured exporters
func RegisterHTTPClientView() {
	view.Register(HTTPClientRequestCountView, HTTPClientRequestDurationView, HTTPClientRequestSizeView)
}

// RegisterHTTPServerView registers the standard HTTPServer view.
// It must be called to see metrics in the configured exporters
func RegisterHTTPServerView() {
	view.Register(HTTPServerRequestCountView, HTTPServerRequestDurationView, HTTPServerRequestSizeView)
}

// RegisterGRPCClientView registers the standard GRPCClient view.
// It must be called to see metrics in the configured exporters
func RegisterGRPCClientView() {
	view.Register(GRPCClientRequestCountView, GRPCClientRequestDurationView, GRPCClientResponseSizeView)
}
