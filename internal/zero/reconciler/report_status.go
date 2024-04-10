package reconciler

import (
	"fmt"

	"github.com/pomerium/pomerium/pkg/health"
)

// sourceAttr is to indicate the source of this health check is not host specific
var sourceAttr = health.StrAttr("source", "pomerium-managed-core")

func (c *service) ReportBundleAppliedSuccess(
	bundleID string,
	metadata map[string]string,
) {
	attr := []health.Attr{sourceAttr}
	for k, v := range metadata {
		attr = append(attr, health.StrAttr(fmt.Sprintf("download-metadata-%s", k), v))
	}
	health.ReportOK(health.ZeroResourceBundle(bundleID), attr...)
}

func (c *service) ReportBundleAppliedFailure(
	bundleID string,
	err error,
) {
	health.ReportError(health.ZeroResourceBundle(bundleID), err, sourceAttr)
}
