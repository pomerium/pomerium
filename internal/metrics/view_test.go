package metrics

import (
	"testing"

	"go.opencensus.io/stats/view"
)

func Test_RegisterView(t *testing.T) {
	RegisterView(HTTPClientViews)
	for _, v := range HTTPClientViews {
		if view.Find(v.Name) != v {
			t.Errorf("Failed to find registered view %s", v.Name)
		}
	}
}

func Test_UnregisterView(t *testing.T) {
	UnRegisterView(HTTPClientViews)
	for _, v := range HTTPClientViews {
		if view.Find(v.Name) == v {
			t.Errorf("Found unregistered view %s", v.Name)
		}
	}
}
