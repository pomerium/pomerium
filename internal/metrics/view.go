package metrics

import (
	"github.com/pomerium/pomerium/internal/log"
	"go.opencensus.io/stats/view"
)

var (
	// HTTPClientViews contains opencensus views for HTTP Client metrics
	HTTPClientViews = []*view.View{HTTPClientRequestCountView, HTTPClientRequestDurationView, HTTPClientResponseSizeView}
	// HTTPServerViews contains opencensus views for HTTP Server metrics
	HTTPServerViews = []*view.View{HTTPServerRequestCountView, HTTPServerRequestDurationView, HTTPServerRequestSizeView, HTTPServerResponseSizeView}
	// GRPCClientViews contains opencensus views for GRPC Client metrics
	GRPCClientViews = []*view.View{GRPCClientRequestCountView, GRPCClientRequestDurationView, GRPCClientResponseSizeView, GRPCClientRequestSizeView}
	// GRPCServerViews contains opencensus views for GRPC Server metrics
	GRPCServerViews = []*view.View{GRPCServerRequestCountView, GRPCServerRequestDurationView, GRPCServerResponseSizeView, GRPCServerRequestSizeView}
	// InfoViews contains opencensus views for Info metrics
	InfoViews = []*view.View{ConfigLastReloadView, ConfigLastReloadSuccessView}
)

// RegisterView registers one of the defined metrics views.  It must be called for metrics to see metrics
// in the configured exporters
func RegisterView(v []*view.View) {
	if err := view.Register(v...); err != nil {
		log.Warn().Str("context", "RegisterView").Err(err).Msg("internal/metrics: Could not register view")
	}
}

// UnRegisterView unregisters one of the defined metrics views.
func UnRegisterView(v []*view.View) {
	view.Unregister(v...)
}
