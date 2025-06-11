package metrics

import (
	"errors"
	"testing"
	"time"

	"go.opencensus.io/stats/view"
)

func Test_RecordStorageOperation(t *testing.T) {
	tests := []struct {
		name     string
		tags     *StorageOperationTags
		duration time.Duration
		want     string
	}{
		{"success", &StorageOperationTags{Operation: "test", Backend: "testengine"}, time.Millisecond * 5, "{ { {backend testengine}{operation test}{result success}{service databroker} }&{1 5 5 5 0"},
		{"error", &StorageOperationTags{Operation: "failtest", Backend: "failengine", Error: errors.New("failure")}, time.Millisecond * 5, "{ { {backend failengine}{operation failtest}{result error}{service databroker} }&{1 5 5 5 0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view.Unregister(StorageViews...)
			view.Register(StorageViews...)
			RecordStorageOperation(t.Context(), tt.tags, tt.duration)

			testDataRetrieval(StorageOperationDurationView, t, tt.want)
		})
	}
}
