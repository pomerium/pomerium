package metrics

import (
	"strings"
	"testing"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
)

func testDataRetrieval(measure stats.Measure, t *testing.T, want string) {
	name := measure.Name()
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
