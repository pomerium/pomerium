package reconciler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

type downloadOptions struct {
	requestCacheEntry  *BundleCacheEntry
	responseCacheEntry *BundleCacheEntry
}

// DownloadOption is an option for downloading a bundle
type DownloadOption func(*downloadOptions)

// WithCacheEntry sets the cache entry to use for the request.
func WithCacheEntry(entry BundleCacheEntry) DownloadOption {
	return func(opts *downloadOptions) {
		opts.requestCacheEntry = &entry
	}
}

// WithUpdateCacheEntry updates the cache entry with the values from the response.
func WithUpdateCacheEntry(dst *BundleCacheEntry) DownloadOption {
	return func(opts *downloadOptions) {
		opts.responseCacheEntry = dst
	}
}

func getDownloadOptions(opts ...DownloadOption) downloadOptions {
	var options downloadOptions
	for _, opt := range opts {
		opt(&options)
	}
	return options
}

func (opt *downloadOptions) updateRequest(req *http.Request) {
	if opt.requestCacheEntry != nil {
		req.Header.Set("If-None-Match", opt.requestCacheEntry.ETag)
		req.Header.Set("If-Modified-Since", opt.requestCacheEntry.LastModified.Format(http.TimeFormat))
	}
}

func (opt *downloadOptions) updateFromResponse(resp *http.Response) error {
	if opt.responseCacheEntry == nil {
		return nil
	}

	if resp.StatusCode == http.StatusNotModified && opt.requestCacheEntry != nil {
		*opt.responseCacheEntry = *opt.requestCacheEntry
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	return updateBundleCacheEntryFromResponse(opt.responseCacheEntry, resp.Header)
}

// DownloadBundleIfChanged downloads the bundle if it has changed.
func (c *service) DownloadBundleIfChanged(
	ctx context.Context,
	dst io.Writer,
	bundleKey string,
	opts ...DownloadOption,
) error {
	options := getDownloadOptions(opts...)

	url, err := c.GetBundleDownloadURL(ctx, bundleKey)
	if err != nil {
		return fmt.Errorf("get download url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	options.updateRequest(req)

	resp, err := c.config.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	err = options.updateFromResponse(resp)
	if err != nil {
		return fmt.Errorf("response: %w", err)
	}

	if resp.StatusCode == http.StatusNotModified {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response: %d/%s", resp.StatusCode, resp.Status)
	}

	_, err = io.Copy(dst, resp.Body)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

func updateBundleCacheEntryFromResponse(dst *BundleCacheEntry, headers http.Header) error {
	txt := headers.Get("Last-Modified")
	if txt == "" {
		return fmt.Errorf("missing last-modified header")
	}

	lastModified, err := time.Parse(http.TimeFormat, txt)
	if err != nil {
		return fmt.Errorf("parse last modified: %w", err)
	}

	etag := headers.Get("ETag")
	if etag == "" {
		return fmt.Errorf("missing etag header")
	}

	dst.LastModified = lastModified
	dst.ETag = etag

	return nil
}
