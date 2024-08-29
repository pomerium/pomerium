package cluster

import (
	"net/http"

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
	_ apierror.APIResponse[EmptyResponse]          = (*ImportConfigurationResp)(nil)
)

// GetBadRequestError implements apierror.APIResponse
func (r *ExchangeClusterIdentityTokenResp) GetBadRequestError() (string, bool) {
	if r.JSON400 == nil {
		return "", false
	}
	return r.JSON400.Error, true
}

// GetInternalServerError implements apierror.APIResponse
func (r *ExchangeClusterIdentityTokenResp) GetInternalServerError() (string, bool) {
	if r.JSON500 == nil {
		return "", false
	}
	return r.JSON500.Error, true
}

// GetValue implements apierror.APIResponse
func (r *ExchangeClusterIdentityTokenResp) GetValue() *ExchangeTokenResponse {
	return r.JSON200
}

// GetHTTPResponse implements apierror.APIResponse
func (r *ExchangeClusterIdentityTokenResp) GetHTTPResponse() *http.Response {
	return r.HTTPResponse
}

// GetBadRequestError implements apierror.APIResponse
func (r *GetClusterBootstrapConfigResp) GetBadRequestError() (string, bool) {
	if r.JSON400 == nil {
		return "", false
	}
	return r.JSON400.Error, true
}

// GetInternalServerError implements apierror.APIResponse
func (r *GetClusterBootstrapConfigResp) GetInternalServerError() (string, bool) {
	if r.JSON500 == nil {
		return "", false
	}
	return r.JSON500.Error, true
}

// GetValue implements apierror.APIResponse
func (r *GetClusterBootstrapConfigResp) GetValue() *BootstrapConfig {
	return r.JSON200
}

// GetHTTPResponse implements apierror.APIResponse
func (r *GetClusterBootstrapConfigResp) GetHTTPResponse() *http.Response {
	return r.HTTPResponse
}

// GetBadRequestError implements apierror.APIResponse
func (r *GetClusterResourceBundlesResp) GetBadRequestError() (string, bool) {
	if r.JSON400 == nil {
		return "", false
	}
	return r.JSON400.Error, true
}

// GetInternalServerError implements apierror.APIResponse
func (r *GetClusterResourceBundlesResp) GetInternalServerError() (string, bool) {
	if r.JSON500 == nil {
		return "", false
	}
	return r.JSON500.Error, true
}

// GetValue implements apierror.APIResponse
func (r *GetClusterResourceBundlesResp) GetValue() *GetBundlesResponse {
	return r.JSON200
}

// GetHTTPResponse implements apierror.APIResponse
func (r *GetClusterResourceBundlesResp) GetHTTPResponse() *http.Response {
	return r.HTTPResponse
}

// GetBadRequestError implements apierror.APIResponse
func (r *DownloadClusterResourceBundleResp) GetBadRequestError() (string, bool) {
	if r.JSON400 == nil {
		return "", false
	}
	return r.JSON400.Error, true
}

// GetInternalServerError implements apierror.APIResponse
func (r *DownloadClusterResourceBundleResp) GetInternalServerError() (string, bool) {
	if r.JSON500 == nil {
		return "", false
	}
	return r.JSON500.Error, true
}

// GetValue implements apierror.APIResponse
func (r *DownloadClusterResourceBundleResp) GetValue() *DownloadBundleResponse {
	return r.JSON200
}

// GetHTTPResponse implements apierror.APIResponse
func (r *DownloadClusterResourceBundleResp) GetHTTPResponse() *http.Response {
	return r.HTTPResponse
}

// GetBadRequestError implements apierror.APIResponse
func (r *ReportClusterResourceBundleStatusResp) GetBadRequestError() (string, bool) {
	if r.JSON400 == nil {
		return "", false
	}
	return r.JSON400.Error, true
}

// GetInternalServerError implements apierror.APIResponse
func (r *ReportClusterResourceBundleStatusResp) GetInternalServerError() (string, bool) {
	if r.JSON500 == nil {
		return "", false
	}
	return r.JSON500.Error, true
}

// GetValue implements apierror.APIResponse
func (r *ReportClusterResourceBundleStatusResp) GetValue() *EmptyResponse {
	return &EmptyResponse{}
}

// GetHTTPResponse implements apierror.APIResponse
func (r *ReportClusterResourceBundleStatusResp) GetHTTPResponse() *http.Response {
	return r.HTTPResponse
}

func (r *ImportConfigurationResp) GetBadRequestError() (string, bool) {
	if r.JSON400 == nil {
		return "", false
	}
	return r.JSON400.Error, true
}

func (r *ImportConfigurationResp) GetInternalServerError() (string, bool) {
	if r.JSON500 == nil {
		return "", false
	}
	return r.JSON500.Error, true
}

func (r *ImportConfigurationResp) GetValue() *EmptyResponse {
	if r.StatusCode()/100 != 2 {
		return nil
	}
	return &EmptyResponse{}
}

func (r *ImportConfigurationResp) GetHTTPResponse() *http.Response {
	return r.HTTPResponse
}
