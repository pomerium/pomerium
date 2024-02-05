// Package cluster provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen/v2 version v2.1.0 DO NOT EDIT.
package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/oapi-codegen/runtime"
)

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// GetClusterBootstrapConfig request
	GetClusterBootstrapConfig(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetClusterResourceBundles request
	GetClusterResourceBundles(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// DownloadClusterResourceBundle request
	DownloadClusterResourceBundle(ctx context.Context, bundleId BundleId, reqEditors ...RequestEditorFn) (*http.Response, error)

	// ReportClusterResourceBundleStatusWithBody request with any body
	ReportClusterResourceBundleStatusWithBody(ctx context.Context, bundleId BundleId, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	ReportClusterResourceBundleStatus(ctx context.Context, bundleId BundleId, body ReportClusterResourceBundleStatusJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// ExchangeClusterIdentityTokenWithBody request with any body
	ExchangeClusterIdentityTokenWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	ExchangeClusterIdentityToken(ctx context.Context, body ExchangeClusterIdentityTokenJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) GetClusterBootstrapConfig(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetClusterBootstrapConfigRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetClusterResourceBundles(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetClusterResourceBundlesRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) DownloadClusterResourceBundle(ctx context.Context, bundleId BundleId, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewDownloadClusterResourceBundleRequest(c.Server, bundleId)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ReportClusterResourceBundleStatusWithBody(ctx context.Context, bundleId BundleId, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewReportClusterResourceBundleStatusRequestWithBody(c.Server, bundleId, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ReportClusterResourceBundleStatus(ctx context.Context, bundleId BundleId, body ReportClusterResourceBundleStatusJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewReportClusterResourceBundleStatusRequest(c.Server, bundleId, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ExchangeClusterIdentityTokenWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewExchangeClusterIdentityTokenRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ExchangeClusterIdentityToken(ctx context.Context, body ExchangeClusterIdentityTokenJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewExchangeClusterIdentityTokenRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewGetClusterBootstrapConfigRequest generates requests for GetClusterBootstrapConfig
func NewGetClusterBootstrapConfigRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/bootstrap")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetClusterResourceBundlesRequest generates requests for GetClusterResourceBundles
func NewGetClusterResourceBundlesRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/bundles")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewDownloadClusterResourceBundleRequest generates requests for DownloadClusterResourceBundle
func NewDownloadClusterResourceBundleRequest(server string, bundleId BundleId) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "bundleId", runtime.ParamLocationPath, bundleId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/bundles/%s/download", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewReportClusterResourceBundleStatusRequest calls the generic ReportClusterResourceBundleStatus builder with application/json body
func NewReportClusterResourceBundleStatusRequest(server string, bundleId BundleId, body ReportClusterResourceBundleStatusJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewReportClusterResourceBundleStatusRequestWithBody(server, bundleId, "application/json", bodyReader)
}

// NewReportClusterResourceBundleStatusRequestWithBody generates requests for ReportClusterResourceBundleStatus with any type of body
func NewReportClusterResourceBundleStatusRequestWithBody(server string, bundleId BundleId, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "bundleId", runtime.ParamLocationPath, bundleId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/bundles/%s/status", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewExchangeClusterIdentityTokenRequest calls the generic ExchangeClusterIdentityToken builder with application/json body
func NewExchangeClusterIdentityTokenRequest(server string, body ExchangeClusterIdentityTokenJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewExchangeClusterIdentityTokenRequestWithBody(server, "application/json", bodyReader)
}

// NewExchangeClusterIdentityTokenRequestWithBody generates requests for ExchangeClusterIdentityToken with any type of body
func NewExchangeClusterIdentityTokenRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/exchangeToken")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// GetClusterBootstrapConfigWithResponse request
	GetClusterBootstrapConfigWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*GetClusterBootstrapConfigResp, error)

	// GetClusterResourceBundlesWithResponse request
	GetClusterResourceBundlesWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*GetClusterResourceBundlesResp, error)

	// DownloadClusterResourceBundleWithResponse request
	DownloadClusterResourceBundleWithResponse(ctx context.Context, bundleId BundleId, reqEditors ...RequestEditorFn) (*DownloadClusterResourceBundleResp, error)

	// ReportClusterResourceBundleStatusWithBodyWithResponse request with any body
	ReportClusterResourceBundleStatusWithBodyWithResponse(ctx context.Context, bundleId BundleId, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*ReportClusterResourceBundleStatusResp, error)

	ReportClusterResourceBundleStatusWithResponse(ctx context.Context, bundleId BundleId, body ReportClusterResourceBundleStatusJSONRequestBody, reqEditors ...RequestEditorFn) (*ReportClusterResourceBundleStatusResp, error)

	// ExchangeClusterIdentityTokenWithBodyWithResponse request with any body
	ExchangeClusterIdentityTokenWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*ExchangeClusterIdentityTokenResp, error)

	ExchangeClusterIdentityTokenWithResponse(ctx context.Context, body ExchangeClusterIdentityTokenJSONRequestBody, reqEditors ...RequestEditorFn) (*ExchangeClusterIdentityTokenResp, error)
}

type GetClusterBootstrapConfigResp struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *GetBootstrapConfigResponse
	JSON400      *ErrorResponse
	JSON500      *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r GetClusterBootstrapConfigResp) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetClusterBootstrapConfigResp) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetClusterResourceBundlesResp struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *GetBundlesResponse
	JSON400      *ErrorResponse
	JSON500      *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r GetClusterResourceBundlesResp) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetClusterResourceBundlesResp) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type DownloadClusterResourceBundleResp struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *DownloadBundleResponse
	JSON400      *ErrorResponse
	JSON404      *ErrorResponse
	JSON500      *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r DownloadClusterResourceBundleResp) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r DownloadClusterResourceBundleResp) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type ReportClusterResourceBundleStatusResp struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON400      *ErrorResponse
	JSON500      *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r ReportClusterResourceBundleStatusResp) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ReportClusterResourceBundleStatusResp) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type ExchangeClusterIdentityTokenResp struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *ExchangeTokenResponse
	JSON400      *ErrorResponse
	JSON500      *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r ExchangeClusterIdentityTokenResp) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ExchangeClusterIdentityTokenResp) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// GetClusterBootstrapConfigWithResponse request returning *GetClusterBootstrapConfigResp
func (c *ClientWithResponses) GetClusterBootstrapConfigWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*GetClusterBootstrapConfigResp, error) {
	rsp, err := c.GetClusterBootstrapConfig(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetClusterBootstrapConfigResp(rsp)
}

// GetClusterResourceBundlesWithResponse request returning *GetClusterResourceBundlesResp
func (c *ClientWithResponses) GetClusterResourceBundlesWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*GetClusterResourceBundlesResp, error) {
	rsp, err := c.GetClusterResourceBundles(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetClusterResourceBundlesResp(rsp)
}

// DownloadClusterResourceBundleWithResponse request returning *DownloadClusterResourceBundleResp
func (c *ClientWithResponses) DownloadClusterResourceBundleWithResponse(ctx context.Context, bundleId BundleId, reqEditors ...RequestEditorFn) (*DownloadClusterResourceBundleResp, error) {
	rsp, err := c.DownloadClusterResourceBundle(ctx, bundleId, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseDownloadClusterResourceBundleResp(rsp)
}

// ReportClusterResourceBundleStatusWithBodyWithResponse request with arbitrary body returning *ReportClusterResourceBundleStatusResp
func (c *ClientWithResponses) ReportClusterResourceBundleStatusWithBodyWithResponse(ctx context.Context, bundleId BundleId, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*ReportClusterResourceBundleStatusResp, error) {
	rsp, err := c.ReportClusterResourceBundleStatusWithBody(ctx, bundleId, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseReportClusterResourceBundleStatusResp(rsp)
}

func (c *ClientWithResponses) ReportClusterResourceBundleStatusWithResponse(ctx context.Context, bundleId BundleId, body ReportClusterResourceBundleStatusJSONRequestBody, reqEditors ...RequestEditorFn) (*ReportClusterResourceBundleStatusResp, error) {
	rsp, err := c.ReportClusterResourceBundleStatus(ctx, bundleId, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseReportClusterResourceBundleStatusResp(rsp)
}

// ExchangeClusterIdentityTokenWithBodyWithResponse request with arbitrary body returning *ExchangeClusterIdentityTokenResp
func (c *ClientWithResponses) ExchangeClusterIdentityTokenWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*ExchangeClusterIdentityTokenResp, error) {
	rsp, err := c.ExchangeClusterIdentityTokenWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseExchangeClusterIdentityTokenResp(rsp)
}

func (c *ClientWithResponses) ExchangeClusterIdentityTokenWithResponse(ctx context.Context, body ExchangeClusterIdentityTokenJSONRequestBody, reqEditors ...RequestEditorFn) (*ExchangeClusterIdentityTokenResp, error) {
	rsp, err := c.ExchangeClusterIdentityToken(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseExchangeClusterIdentityTokenResp(rsp)
}

// ParseGetClusterBootstrapConfigResp parses an HTTP response from a GetClusterBootstrapConfigWithResponse call
func ParseGetClusterBootstrapConfigResp(rsp *http.Response) (*GetClusterBootstrapConfigResp, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetClusterBootstrapConfigResp{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest GetBootstrapConfigResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseGetClusterResourceBundlesResp parses an HTTP response from a GetClusterResourceBundlesWithResponse call
func ParseGetClusterResourceBundlesResp(rsp *http.Response) (*GetClusterResourceBundlesResp, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetClusterResourceBundlesResp{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest GetBundlesResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseDownloadClusterResourceBundleResp parses an HTTP response from a DownloadClusterResourceBundleWithResponse call
func ParseDownloadClusterResourceBundleResp(rsp *http.Response) (*DownloadClusterResourceBundleResp, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &DownloadClusterResourceBundleResp{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest DownloadBundleResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 404:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON404 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseReportClusterResourceBundleStatusResp parses an HTTP response from a ReportClusterResourceBundleStatusWithResponse call
func ParseReportClusterResourceBundleStatusResp(rsp *http.Response) (*ReportClusterResourceBundleStatusResp, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &ReportClusterResourceBundleStatusResp{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseExchangeClusterIdentityTokenResp parses an HTTP response from a ExchangeClusterIdentityTokenWithResponse call
func ParseExchangeClusterIdentityTokenResp(rsp *http.Response) (*ExchangeClusterIdentityTokenResp, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &ExchangeClusterIdentityTokenResp{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest ExchangeTokenResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}
