package reconciler

import (
	"context"

	"github.com/pomerium/pomerium/internal/log"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

const (
	// BundleStatusFailureDatabrokerError indicates a failure due to a databroker error
	BundleStatusFailureDatabrokerError = cluster_api.DatabrokerError
	// BundleStatusFailureDownloadError indicates a failure due to a download error
	BundleStatusFailureDownloadError = cluster_api.DownloadError
	// BundleStatusFailureInvalidBundle indicates a failure due to an invalid bundle
	BundleStatusFailureInvalidBundle = cluster_api.InvalidBundle
	// BundleStatusFailureIO indicates a failure due to an IO error
	BundleStatusFailureIO = cluster_api.IoError
	// BundleStatusFailureUnknownError indicates a failure due to an unknown error
	BundleStatusFailureUnknownError = cluster_api.UnknownError
)

func (c *service) ReportBundleAppliedSuccess(
	ctx context.Context,
	bundleID string,
	metadata map[string]string,
) {
	err := c.config.api.ReportBundleAppliedSuccess(ctx, bundleID, metadata)
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("reconciler: error reporting bundle status")
	}
}

func (c *service) ReportBundleAppliedFailure(
	ctx context.Context,
	bundleID string,
	source cluster_api.BundleStatusFailureSource,
	err error,
) {
	err = c.config.api.ReportBundleAppliedFailure(ctx, bundleID, source, err)
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("reconciler: error reporting bundle status")
	}
}
