package usagereporter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/zero/cluster"
)

func Test_convertUsageReporterRecords(t *testing.T) {
	t.Parallel()

	tm1 := time.Date(2024, time.September, 11, 11, 56, 0, 0, time.UTC)

	assert.Empty(t, convertUsageReporterRecords("XXX", nil))
	assert.Equal(t, []cluster.ReportUsageUser{{
		LastSignedInAt:    tm1,
		PseudonymousId:    "T9V1yL/UueF/LVuF6XjoSNde0INElXG10zKepmyPke8=",
		PseudonymousEmail: "8w5rtnZyv0EGkpHmTlkmupgb1jCzn/IxGCfvpdGGnvI=",
	}}, convertUsageReporterRecords("XXX", []usageReporterRecord{{
		userID:         "ID",
		userEmail:      "EMAIL@example.com",
		lastSignedInAt: tm1,
	}}))
	assert.Equal(t, []cluster.ReportUsageUser{{
		LastSignedInAt: tm1,
		PseudonymousId: "T9V1yL/UueF/LVuF6XjoSNde0INElXG10zKepmyPke8=",
	}}, convertUsageReporterRecords("XXX", []usageReporterRecord{{
		userID:         "ID",
		lastSignedInAt: tm1,
	}}), "should leave empty email")
}
