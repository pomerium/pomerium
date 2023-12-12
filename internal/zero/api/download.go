package zero

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/pomerium/pomerium/internal/zero/apierror"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

const (
	maxErrorResponseBodySize = 2 << 14 // 32kb
	maxUncompressedBlobSize  = 2 << 30 // 1gb
)

// DownloadClusterResourceBundle downloads given cluster resource bundle to given writer.
func (api *API) DownloadClusterResourceBundle(
	ctx context.Context,
	dst io.Writer,
	id string,
	current *DownloadConditional,
) (*DownloadResult, error) {
	req, err := api.getDownloadRequest(ctx, id, current)
	if err != nil {
		return nil, fmt.Errorf("get download request: %w", err)
	}

	resp, err := api.cfg.httpClient.Do(req.Request)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return &DownloadResult{NotModified: true}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, httpDownloadError(ctx, resp)
	}

	var r io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer zr.Close()

		r = io.LimitReader(zr, maxUncompressedBlobSize)
	}

	_, err = io.Copy(dst, r)
	if err != nil {
		return nil, fmt.Errorf("write body: %w", err)
	}

	updated, err := newConditionalFromResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("cannot obtain cache conditions from response: %w", err)
	}

	return &DownloadResult{
		DownloadConditional: updated,
		Metadata:            extractMetadata(resp.Header, req.CaptureHeaders),
	}, nil
}

type downloadRequest struct {
	*http.Request
	cluster_api.DownloadCacheEntry
}

func (api *API) getDownloadRequest(ctx context.Context, id string, current *DownloadConditional) (*downloadRequest, error) {
	params, err := api.getDownloadParams(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get download URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, params.URL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Accept-Encoding", "gzip")

	err = current.SetHeaders(req)
	if err != nil {
		return nil, fmt.Errorf("set conditional download headers: %w", err)
	}

	return &downloadRequest{
		Request:            req,
		DownloadCacheEntry: *params,
	}, nil
}

func (api *API) getDownloadParams(ctx context.Context, id string) (*cluster_api.DownloadCacheEntry, error) {
	param, ok := api.downloadURLCache.Get(id, api.cfg.downloadURLCacheTTL)
	if ok {
		return param, nil
	}

	return api.updateBundleDownloadParams(ctx, id)
}

func (api *API) updateBundleDownloadParams(ctx context.Context, id string) (*cluster_api.DownloadCacheEntry, error) {
	now := time.Now()

	resp, err := apierror.CheckResponse[cluster_api.DownloadBundleResponse](
		api.cluster.DownloadClusterResourceBundleWithResponse(ctx, id),
	)
	if err != nil {
		return nil, fmt.Errorf("get bundle download URL: %w", err)
	}

	expiresSeconds, err := strconv.ParseInt(resp.ExpiresInSeconds, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse expiration: %w", err)
	}

	u, err := url.Parse(resp.Url)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	param := cluster_api.DownloadCacheEntry{
		URL:            *u,
		ExpiresAt:      now.Add(time.Duration(expiresSeconds) * time.Second),
		CaptureHeaders: resp.CaptureMetadataHeaders,
	}
	api.downloadURLCache.Set(id, param)
	return &param, nil
}

// DownloadResult contains the result of a download operation
type DownloadResult struct {
	// NotModified is true if the bundle has not been modified
	NotModified bool
	// DownloadConditional contains the new conditional
	*DownloadConditional
	// Metadata contains the metadata of the downloaded bundle
	Metadata map[string]string
}

// DownloadConditional contains the conditional headers for a download operation
type DownloadConditional struct {
	ETag         string
	LastModified string
}

// Validate validates the conditional headers
func (c *DownloadConditional) Validate() error {
	if c.ETag == "" && c.LastModified == "" {
		return fmt.Errorf("either ETag or LastModified must be set")
	}
	return nil
}

// SetHeaders sets the conditional headers on the given request
func (c *DownloadConditional) SetHeaders(req *http.Request) error {
	if c == nil {
		return nil
	}
	if err := c.Validate(); err != nil {
		return err
	}
	req.Header.Set("If-None-Match", c.ETag)
	req.Header.Set("If-Modified-Since", c.LastModified)
	return nil
}

func newConditionalFromResponse(resp *http.Response) (*DownloadConditional, error) {
	c := &DownloadConditional{
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

type xmlError struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
	Details string   `xml:"Details"`
}

func (e xmlError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func tryXMLError(body []byte) (bool, error) {
	var xmlErr xmlError
	err := xml.Unmarshal(body, &xmlErr)
	if err != nil {
		return false, fmt.Errorf("unmarshal xml error: %w", err)
	}

	return true, xmlErr
}

func httpDownloadError(ctx context.Context, resp *http.Response) error {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, io.LimitReader(resp.Body, maxErrorResponseBodySize))

	if isXML(resp.Header.Get("Content-Type")) {
		ok, err := tryXMLError(buf.Bytes())
		if ok {
			return err
		}
	}

	log.Ctx(ctx).Debug().Err(err).
		Str("error", resp.Status).
		Str("body", buf.String()).Msg("bundle download error")

	return fmt.Errorf("download error: %s", resp.Status)
}

// isXML parses content-type for application/xml
func isXML(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == "application/xml"
}

func extractMetadata(header http.Header, keys []string) map[string]string {
	m := make(map[string]string)
	for _, k := range keys {
		v := header.Get(k)
		if v != "" {
			m[k] = v
		}
	}
	return m
}
