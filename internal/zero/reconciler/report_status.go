package reconciler

import (
	"fmt"

	"github.com/pomerium/pomerium/pkg/health"
)

func (c *service) ReportBundleAppliedSuccess(
	bundleID string,
	metadata map[string]string,
) {
	var attr []health.Attr
	for k, v := range metadata {
		attr = append(attr, health.StrAttr(fmt.Sprintf("download-metadata-%s", k), v))
	}
	health.ReportOK(health.ZeroResourceBundle(bundleID), attr...)
}

func (c *service) ReportBundleAppliedFailure(
	bundleID string,
	err error,
) {
	health.ReportError(health.ZeroResourceBundle(bundleID), err)
}
