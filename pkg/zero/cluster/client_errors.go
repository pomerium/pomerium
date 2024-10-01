package cluster

import (
	"github.com/pomerium/pomerium/internal/zero/apierror"
)

// EmptyResponse is an empty response
type EmptyResponse struct{}

var (
	_ apierror.APIResponse[ExchangeTokenResponse]  = (*ExchangeClusterIdentityTokenResp)(nil)
	_ apierror.APIResponse[BootstrapConfig]        = (*GetClusterBootstrapConfigResp)(nil)
	_ apierror.APIResponse[GetBundlesResponse]     = (*GetClusterResourceBundlesResp)(nil)
	_ apierror.APIResponse[DownloadBundleResponse] = (*DownloadClusterResourceBundleResp)(nil)
	_ apierror.APIResponse[EmptyResponse]          = (*ReportClusterResourceBundleStatusResp)(nil)
	_ apierror.APIResponse[ImportResponse]         = (*ImportConfigurationResp)(nil)
	_ apierror.APIResponse[ConfigQuotas]           = (*GetQuotasResp)(nil)
)
