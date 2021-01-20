package authorize

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
	"google.golang.org/api/idtoken"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

var (
	gpcIdentityTokenExpiration       = time.Minute * 45 // tokens expire after one hour according to the GCP docs
	gcpIdentityDocURL                = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
	gcpIdentityNow                   = time.Now
	gcpIdentityMaxBodySize     int64 = 1024 * 1024 * 10
)

type gcpIdentityTokenSource struct {
	audience     string
	singleflight singleflight.Group
}

func (src *gcpIdentityTokenSource) Token() (*oauth2.Token, error) {
	res, err, _ := src.singleflight.Do("", func() (interface{}, error) {
		req, err := http.NewRequestWithContext(context.Background(), "GET", gcpIdentityDocURL+"?"+url.Values{
			"format":   {"full"},
			"audience": {src.audience},
		}.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Add("Metadata-Flavor", "Google")

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = res.Body.Close() }()

		bs, err := ioutil.ReadAll(io.LimitReader(res.Body, gcpIdentityMaxBodySize))
		if err != nil {
			return nil, err
		}
		return string(bs), nil
	})
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: strings.TrimSpace(res.(string)),
		TokenType:   "bearer",
		Expiry:      gcpIdentityNow().Add(gpcIdentityTokenExpiration),
	}, nil
}

type gcpTokenSourceKey struct {
	serviceAccount string
	audience       string
}

var gcpTokenSources = struct {
	sync.Mutex
	m map[gcpTokenSourceKey]oauth2.TokenSource
}{
	m: make(map[gcpTokenSourceKey]oauth2.TokenSource),
}

func normalizeServiceAccount(serviceAccount string) (string, error) {
	serviceAccount = strings.TrimSpace(serviceAccount)

	// the service account can be base64 encoded
	if !strings.HasPrefix(serviceAccount, "{") {
		bs, err := base64.StdEncoding.DecodeString(serviceAccount)
		if err != nil {
			return "", err
		}
		serviceAccount = string(bs)
	}
	return serviceAccount, nil
}

func getGoogleCloudServerlessTokenSource(serviceAccount, audience string) (oauth2.TokenSource, error) {
	key := gcpTokenSourceKey{
		serviceAccount: serviceAccount,
		audience:       audience,
	}

	gcpTokenSources.Lock()
	defer gcpTokenSources.Unlock()

	src, ok := gcpTokenSources.m[key]
	if ok {
		return src, nil
	}

	if serviceAccount == "" {
		src = oauth2.ReuseTokenSource(new(oauth2.Token), &gcpIdentityTokenSource{
			audience: audience,
		})
	} else {
		serviceAccount, err := normalizeServiceAccount(serviceAccount)
		if err != nil {
			return nil, err
		}
		newSrc, err := idtoken.NewTokenSource(context.Background(), audience, idtoken.WithCredentialsJSON([]byte(serviceAccount)))
		if err != nil {
			return nil, err
		}
		src = newSrc
	}

	gcpTokenSources.m[key] = src

	return src, nil
}

func (a *Authorize) getGoogleCloudServerlessAuthenticationHeaders(reply *evaluator.Result) ([]*envoy_api_v2_core.HeaderValueOption, error) {
	if reply.MatchingPolicy == nil || !reply.MatchingPolicy.EnableGoogleCloudServerlessAuthentication {
		return nil, nil
	}

	serviceAccount := a.currentOptions.Load().GoogleCloudServerlessAuthenticationServiceAccount
	var hostname string
	if len(reply.MatchingPolicy.Destinations) > 0 {
		hostname = reply.MatchingPolicy.Destinations[0].Hostname()
	}
	audience := fmt.Sprintf("https://%s", hostname)

	src, err := getGoogleCloudServerlessTokenSource(serviceAccount, audience)
	if err != nil {
		return nil, err
	}

	tok, err := src.Token()
	if err != nil {
		return nil, err
	}

	return []*envoy_api_v2_core.HeaderValueOption{
		mkHeader("Authorization", "Bearer "+tok.AccessToken, false),
	}, nil
}
