package telemetry

import (
	"go.opencensus.io/stats/view"
)

var (
	// DefaultViews are a set of default views to view HTTP and GRPC metrics.
	DefaultViews = [][]*view.View{
		GRPCServerViews,
		HTTPServerViews,
		GRPCClientViews,
		GRPCServerViews}

	// HTTPClientViews contains opencensus views for HTTP Client metrics.
	HTTPClientViews = []*view.View{
		HTTPClientRequestCountView,
		HTTPClientRequestDurationView,
		HTTPClientResponseSizeView}
	// HTTPServerViews contains opencensus views for HTTP Server metrics.
	HTTPServerViews = []*view.View{
		HTTPServerRequestCountView,
		HTTPServerRequestDurationView,
		HTTPServerRequestSizeView,
		HTTPServerResponseSizeView}
	// GRPCClientViews contains opencensus views for GRPC Client metrics.
	GRPCClientViews = []*view.View{
		GRPCClientRequestCountView,
		GRPCClientRequestDurationView,
		GRPCClientResponseSizeView,
		GRPCClientRequestSizeView}
	// GRPCServerViews contains opencensus views for GRPC Server metrics.
	GRPCServerViews = []*view.View{
		GRPCServerRequestCountView,
		GRPCServerRequestDurationView,
		GRPCServerResponseSizeView,
		GRPCServerRequestSizeView}
)

func registerDefaultViews() error {
	var views []*view.View
	for _, v := range DefaultViews {
		views = append(views, v...)
	}
	return registerView(views...)
}

// registerView registers one of the defined metrics views. It must be called
// for metrics to see metrics in the configured exporters.
func registerView(v ...*view.View) error {
	return view.Register(v...)
}

// UnRegisterView unregisters one of the defined metrics views.
func unRegisterView(v ...*view.View) {
	view.Unregister(v...)
}
