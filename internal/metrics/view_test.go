package metrics

import (
	"testing"

	"go.opencensus.io/stats/view"
)

func Test_RegisterHTTPClientView(t *testing.T) {
	RegisterHTTPClientView()
	for _, v := range []*view.View{HTTPClientRequestCountView, HTTPClientRequestDurationView, HTTPClientResponseSizeView} {
		if view.Find(v.Name) != v {
			t.Errorf("Failed to find registered view %s", v.Name)
		}
	}
}

func Test_RegisterHTTPServerView(t *testing.T) {
	RegisterHTTPServerView()
	for _, v := range []*view.View{HTTPServerRequestCountView, HTTPServerRequestDurationView, HTTPServerRequestSizeView} {
		if view.Find(v.Name) != v {
			t.Errorf("Failed to find registered view %s", v.Name)
		}
	}
}

func Test_RegisterGRPCClientView(t *testing.T) {
	RegisterGRPCClientView()
	for _, v := range []*view.View{GRPCClientRequestCountView, GRPCClientRequestDurationView, GRPCClientResponseSizeView} {
		if view.Find(v.Name) != v {
			t.Errorf("Failed to find registered view %s", v.Name)
		}
	}
}
