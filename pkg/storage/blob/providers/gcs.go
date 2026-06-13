package providers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"gocloud.dev/blob"
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/gcp"
	"golang.org/x/oauth2/google"

	"github.com/pomerium/pomerium/internal/log"
)

type gcsCredsWrapper struct {
	opener *gcsblob.URLOpener
	err    error

	credentialLoaders []CredentialsLoader
}

func (g *gcsCredsWrapper) OpenBucketURL(ctx context.Context, u *url.URL) (*blob.Bucket, error) {
	var creds *google.Credentials
	var opts gcsblob.Options
	var err error

	sources := []string{}
	for _, credLoader := range g.credentialLoaders {
		sources = append(sources, credLoader.Name())
		log.Ctx(ctx).Info().Str("source", credLoader.Name()).Str("provider", "gcs").Msg("trying to load credentials for bucket")
		creds, opts, err = credLoader.LoadGCPCredentials(ctx, u)
		if err == nil {
			log.Ctx(ctx).Info().Str("source", credLoader.Name()).Str("provider", "gcs").Msg("loaded credential for bucket")
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials from sources : %s", strings.Join(sources, ","))
	}
	client, err := gcp.NewHTTPClient(gcp.DefaultTransport(), creds.TokenSource)
	if err != nil {
		g.err = err
	}
	g.opener = &gcsblob.URLOpener{Client: client, Options: opts}
	if g.err != nil {
		return nil, fmt.Errorf("open bucket %v: %w", u, g.err)
	}
	return g.opener.OpenBucketURL(ctx, u)
}
