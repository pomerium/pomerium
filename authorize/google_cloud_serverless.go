package authorize

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"golang.org/x/sync/singleflight"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

var (
	gpcIdentityTokenExpiration  = time.Hour // tokens expire after one hour according to the GCP docs
	gcpIdentityTokenGracePeriod = time.Minute * 10
	gcpIdentityDocURL           = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
	gcpIdentityTokenSource      = NewGCPIdentityTokenSource()
)

// A GCPIdentityToken is an identity token for a service account.
type GCPIdentityToken struct {
	Audience string
	Token    string
	Expires  time.Time
}

// The GCPIdentityTokenSource retrieves identity tokens for service accounts. It single-flights requests and caches
// tokens.
type GCPIdentityTokenSource struct {
	singleflight.Group

	mu     sync.Mutex
	tokens map[string]GCPIdentityToken
}

// NewGCPIdentityTokenSource creates a new GCPIdentityTokenSource.
func NewGCPIdentityTokenSource() *GCPIdentityTokenSource {
	return &GCPIdentityTokenSource{
		tokens: make(map[string]GCPIdentityToken),
	}
}

// Get gets an identity token.
func (src *GCPIdentityTokenSource) Get(ctx context.Context, audience string) (string, error) {
	v, err, _ := src.Do(audience, func() (interface{}, error) {
		src.mu.Lock()
		tok, ok := src.tokens[audience]
		src.mu.Unlock()

		if ok && tok.Expires.Add(-gcpIdentityTokenGracePeriod).After(time.Now()) {
			return tok, nil
		}

		req, err := http.NewRequestWithContext(ctx, "GET", gcpIdentityDocURL+"?"+url.Values{
			"format":   {"full"},
			"audience": {audience},
		}.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Add("Metadata-Flavor", "Google")

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		bs, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		tok = GCPIdentityToken{
			Audience: audience,
			Token:    strings.TrimSpace(string(bs)),
			Expires:  time.Now().Add(gpcIdentityTokenExpiration),
		}
		src.mu.Lock()
		src.tokens[audience] = tok
		src.mu.Unlock()

		return tok, nil
	})
	if err != nil {
		return "", err
	}
	return v.(GCPIdentityToken).Token, nil
}

func (a *Authorize) getGoogleCloudServerlessAuthenticationHeaders(
	ctx context.Context,
	reply *evaluator.Result,
) ([]*envoy_api_v2_core.HeaderValueOption, error) {
	if reply.MatchingPolicy == nil || !reply.MatchingPolicy.EnableGoogleCloudServerlessAuthentication {
		return nil, nil
	}

	svcAccount := a.currentOptions.Load().GoogleCloudServerlessAuthenticationServiceAccount
	if svcAccount != "" {
		panic("custom service account not implemented")
	}

	audience := fmt.Sprintf("https://%s", reply.MatchingPolicy.Source.Hostname())

	tok, err := gcpIdentityTokenSource.Get(ctx, audience)
	if err != nil {
		return nil, err
	}

	return []*envoy_api_v2_core.HeaderValueOption{
		mkHeader("Authorization", "Bearer "+tok, false),
	}, nil
}
