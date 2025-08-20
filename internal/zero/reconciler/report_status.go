package reconciler

import (
	"github.com/pomerium/pomerium/pkg/health"
)

func (c *service) ReportBundleAppliedSuccess(
	bundleID string,
	metadata map[string]string,
) {
	var attr []health.Attr
	for k, v := range metadata {
		attr = append(attr, health.StrAttr(k, v))
	}
	health.ReportRunning(health.ZeroResourceBundle(bundleID), attr...)
}

func (c *service) ReportBundleAppliedFailure(
	bundleID string,
	err error,
) {
	health.ReportError(health.ZeroResourceBundle(bundleID), err)
}
