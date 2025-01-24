package portal

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"iter"
	"mime"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/sync/semaphore"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// errors
var ErrLogoNotFound = errors.New("logo not found")

// A LogoProvider gets logo urls for routes.
type LogoProvider interface {
	GetLogoURL(ctx context.Context, from, to string) (string, error)
}

// NewLogoProvider creates a new LogoProvider.
func NewLogoProvider() LogoProvider {
	return newFaviconDiscoveryLogoProvider()
}

type faviconCacheValue struct {
	sem    *semaphore.Weighted
	url    string
	err    error
	expiry time.Time
}

type faviconDiscoveryLogoProvider struct {
	mu         sync.Mutex
	cache      map[string]*faviconCacheValue
	successTTL time.Duration
	failureTTL time.Duration
}

func newFaviconDiscoveryLogoProvider() *faviconDiscoveryLogoProvider {
	return &faviconDiscoveryLogoProvider{
		cache:      make(map[string]*faviconCacheValue),
		successTTL: time.Hour,
		failureTTL: 10 * time.Minute,
	}
}

func (p *faviconDiscoveryLogoProvider) GetLogoURL(ctx context.Context, _, to string) (string, error) {
	p.mu.Lock()
	v, ok := p.cache[to]
	if !ok {
		v = &faviconCacheValue{
			sem: semaphore.NewWeighted(1),
		}
		p.cache[to] = v
	}
	p.mu.Unlock()

	// take the semaphore
	err := v.sem.Acquire(ctx, 1)
	if err != nil {
		return "", err
	}
	defer v.sem.Release(1)

	// if we have a valid cached url or error, return it
	if v.expiry.After(time.Now()) {
		return v.url, v.err
	}

	// attempt to discover the logo url and save the url or the error
	v.url, v.err = p.discoverLogoURL(ctx, to)
	if v.err == nil {
		v.expiry = time.Now().Add(p.successTTL)
	} else {
		v.expiry = time.Now().Add(p.failureTTL)
	}

	return v.url, v.err
}

func (p *faviconDiscoveryLogoProvider) discoverLogoURL(ctx context.Context, rawURL string) (string, error) {
	u, err := urlutil.ParseAndValidateURL(rawURL)
	if err != nil {
		return "", ErrLogoNotFound
	}

	if !(u.Scheme == "http" || u.Scheme == "https") {
		return "", ErrLogoNotFound
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}

	t := httputil.GetInsecureTransport()
	c := &http.Client{
		Transport: t,
	}

	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	// look for any logos in the html
	r := io.LimitReader(res.Body, 10*1024)
	for link := range findIconLinksInHTML(r) {
		linkURL, err := urlutil.ParseAndValidateURL(link)
		if err != nil {
			continue
		}

		logoURL := p.fetchLogoURL(ctx, c, u.ResolveReference(linkURL))
		if logoURL != "" {
			return logoURL, nil
		}
	}

	// try just the /favicon.ico
	logoURL := p.fetchLogoURL(ctx, c, u.ResolveReference(&url.URL{Path: "/favicon.ico"}))
	if logoURL != "" {
		return logoURL, nil
	}

	return "", ErrLogoNotFound
}

func (p *faviconDiscoveryLogoProvider) fetchLogoURL(ctx context.Context, client *http.Client, logoURL *url.URL) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, logoURL.String(), nil)
	if err != nil {
		return ""
	}

	res, err := client.Do(req)
	if err != nil {
		log.Ctx(ctx).Debug().Str("url", logoURL.String()).Err(err).Msg("error fetching logo contents")
		return ""
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		log.Ctx(ctx).Debug().Int("status-code", res.StatusCode).Str("url", logoURL.String()).Msg("error fetching logo contents")
		return ""
	}

	const maxImageSize = 1024 * 1024
	bs, err := io.ReadAll(io.LimitReader(res.Body, maxImageSize))
	if err != nil {
		log.Ctx(ctx).Debug().Str("url", logoURL.String()).Err(err).Msg("error reading logo contents")
		return ""
	}

	// first use the Content-Type header to determine the format
	if mtype, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err == nil {
		if isSupportedImageType(mtype) {
			return "data:" + mtype + ";base64," + base64.StdEncoding.EncodeToString(bs)
		}
		log.Ctx(ctx).Debug().Str("mime-type", mtype).Str("url", logoURL.String()).Msg("rejecting logo")
		return ""
	}

	// next try to use mimetype sniffing
	mtype := http.DetectContentType(bs)
	if isSupportedImageType(mtype) {
		return "data:" + mtype + ";base64," + base64.StdEncoding.EncodeToString(bs)
	}

	log.Ctx(ctx).Debug().Str("mime-type", mtype).Str("url", logoURL.String()).Msg("rejecting logo")
	return ""
}

func isSupportedImageType(mtype string) bool {
	return mtype == "image/vnd.microsoft.icon" ||
		mtype == "image/png" ||
		mtype == "image/svg+xml" ||
		mtype == "image/jpeg" ||
		mtype == "image/gif"
}

func findIconLinksInHTML(r io.Reader) iter.Seq[string] {
	return func(yield func(string) bool) {
		z := html.NewTokenizer(r)
		for {
			tt := z.Next()
			if tt == html.ErrorToken {
				return
			}

			switch tt {
			case html.StartTagToken:
				name, attr := parseTag(z)
				if name == "link" && attr["href"] != "" && (attr["rel"] == "shortcut icon" || attr["rel"] == "icon") {
					if !yield(attr["href"]) {
						return
					}
				}
			}
		}
	}
}

func parseTag(z *html.Tokenizer) (name string, attributes map[string]string) {
	n, hasAttr := z.TagName()
	name = string(n)
	if !hasAttr {
		return name, attributes
	}
	attributes = make(map[string]string)
	for {
		k, v, m := z.TagAttr()
		attributes[string(k)] = string(v)
		if !m {
			break
		}
	}
	return name, attributes
}
