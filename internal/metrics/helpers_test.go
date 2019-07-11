package metrics

import (
	"strings"
	"testing"

	"go.opencensus.io/stats/view"
)

func testDataRetrieval(v *view.View, t *testing.T, want string) {
	if v == nil {
		t.Fatalf("%s: nil view passed", t.Name())
	}
	name := v.Name
	data, err := view.RetrieveData(name)

	if err != nil {
		t.Fatalf("%s: failed to retrieve data line %s", name, err)
	}
	if len(data) != 1 {
		t.Errorf("%s: received too many data rows: %d", name, len(data))
	}

	if !strings.HasPrefix(data[0].String(), want) {
		t.Errorf("%s: Found unexpected data row: \nwant: %s\ngot: %s\n", name, want, data[0].String())
	}
}
