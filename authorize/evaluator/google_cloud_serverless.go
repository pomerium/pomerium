package evaluator

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
	"google.golang.org/api/idtoken"

	"github.com/pomerium/pomerium/internal/log"
)

// GCP pre-defined values.
var (
	GCPIdentityTokenExpiration       = time.Minute * 45 // tokens expire after one hour according to the GCP docs
	GCPIdentityDocURL                = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
	GCPIdentityNow                   = time.Now
	GCPIdentityMaxBodySize     int64 = 1024 * 1024 * 10

	getGoogleCloudServerlessHeadersRegoOption = rego.Function2(&rego.Function{
		Name: "get_google_cloud_serverless_headers",
		Decl: types.NewFunction(
			types.Args(types.S, types.S),
			types.NewObject(nil, types.NewDynamicProperty(types.S, types.S)),
		),
	}, func(_ rego.BuiltinContext, op1 *ast.Term, op2 *ast.Term) (*ast.Term, error) {
		serviceAccount, ok := op1.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("invalid service account type: %T", op1)
		}

		audience, ok := op2.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("invalid audience type: %T", op2)
		}

		headers, err := getGoogleCloudServerlessHeaders(string(serviceAccount), string(audience))
		if err != nil {
			log.Error().Err(err).Msg("error retrieving google cloud serverless headers")
			return nil, fmt.Errorf("failed to get google cloud serverless headers: %w", err)
		}
		var kvs [][2]*ast.Term
		for k, v := range headers {
			kvs = append(kvs, [2]*ast.Term{ast.StringTerm(k), ast.StringTerm(v)})
		}

		return ast.ObjectTerm(kvs...), nil
	})
)

type gcpIdentityTokenSource struct {
	audience     string
	singleflight singleflight.Group
}

func (src *gcpIdentityTokenSource) Token() (*oauth2.Token, error) {
	res, err, _ := src.singleflight.Do("", func() (any, error) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, GCPIdentityDocURL+"?"+url.Values{
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

		bs, err := io.ReadAll(io.LimitReader(res.Body, GCPIdentityMaxBodySize))
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
		Expiry:      GCPIdentityNow().Add(GCPIdentityTokenExpiration),
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

func getGoogleCloudServerlessHeaders(serviceAccount, audience string) (map[string]string, error) {
	src, err := getGoogleCloudServerlessTokenSource(serviceAccount, audience)
	if err != nil {
		return nil, fmt.Errorf("error retrieving google cloud serverless token source: %w", err)
	}

	tok, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("error retrieving google cloud serverless token: %w", err)
	}

	return map[string]string{
		"Authorization": "Bearer " + tok.AccessToken,
	}, nil
}
