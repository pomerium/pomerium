package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"cloud.google.com/go/compute/metadata"
	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"github.com/googleapis/gax-go/v2"
	"gocloud.dev/blob"
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/gcp"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

var gcsIdentityOpener = &lazyCredsOpener{}

// https://github.com/google/go-cloud/blob/595f8b60336588551dac6041130593109761eaa0/blob/gcsblob/gcsblob.go#L230-L237
type identityURLOpener struct {
	// Client must be set to a non-nil HTTP client authenticated with
	// Cloud Storage scope or equivalent (unless anonymous=true).
	Client *gcp.HTTPClient

	// Options specifies the default options to pass to OpenBucket.
	Options gcsblob.Options
}

// OpenBucketURL opens the GCS bucket with the same name as the URL's host.
func (o *identityURLOpener) OpenBucketURL(ctx context.Context, u *url.URL) (*blob.Bucket, error) {
	opts, client, err := o.forParams(ctx, u.Query())
	if err != nil {
		return nil, fmt.Errorf("open bucket %v: %w", u, err)
	}
	return gcsblob.OpenBucket(ctx, client, u.Host, opts)
}

// reimplementation of : https://github.com/google/go-cloud/blob/595f8b60336588551dac6041130593109761eaa0/blob/gcsblob/gcsblob.go#L325-L332
func clearOptions(o *gcsblob.Options) {
	o.GoogleAccessID = ""
	o.PrivateKey = nil
	o.SignBytes = nil
	o.MakeSignBytes = nil
}

// reimplementation of private to allow for overriding http round tripper for per-request UserAgent headers
// https://github.com/google/go-cloud/blob/595f8b60336588551dac6041130593109761eaa0/blob/gcsblob/gcsblob.go#L247
func (o *identityURLOpener) forParams(_ context.Context, q url.Values) (*gcsblob.Options, *gcp.HTTPClient, error) {
	for k := range q {
		if k != "access_id" && k != "private_key_path" && k != "anonymous" && k != "universe_domain" {
			return nil, nil, fmt.Errorf("invalid query parameter %q", k)
		}
	}
	opts := new(gcsblob.Options)
	*opts = o.Options
	client := o.Client
	if anon := q.Get("anonymous"); anon != "" {
		isAnon, err := strconv.ParseBool(anon)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid value %q for query parameter \"anonymous\": %w", anon, err)
		}
		if isAnon {
			// !! difference with upstream
			clearOptions(opts)
			client = gcp.NewAnonymousHTTPClient(&identityRoundTripper{
				base: gcp.DefaultTransport(),
			})
		}
	}
	if accessID := q.Get("access_id"); accessID != "" && accessID != opts.GoogleAccessID {
		// !! difference with upstream
		clearOptions(opts)
		if accessID == "-" {
			client = gcp.NewAnonymousHTTPClient(&identityRoundTripper{
				base: gcp.DefaultTransport(),
			})
		} else {
			opts.GoogleAccessID = accessID
		}
	}
	if keyPath := q.Get("private_key_path"); keyPath != "" {
		pk, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, err
		}
		opts.PrivateKey = pk
	} else if _, exists := q["private_key_path"]; exists {
		// A possible default value has been cleared by setting this to an empty value:
		// The private key might have expired, or falling back to SignBytes/MakeSignBytes
		// is intentional such as for tests or involving a key stored in a HSM/TPM.
		opts.PrivateKey = nil
	}
	return opts, client, nil
}

// lazyCredsOpener obtains Application Default Credentials on the first call
// to OpenBucketURL.
// Ref : https://github.com/google/go-cloud/blob/595f8b60336588551dac6041130593109761eaa0/blob/gcsblob/gcsblob.go#L145-L152
type lazyCredsOpener struct {
	init sync.Once
	// !!! difference with upstream
	opener *identityURLOpener
	err    error
}

func (o *lazyCredsOpener) OpenBucketURL(ctx context.Context, u *url.URL) (*blob.Bucket, error) {
	o.init.Do(func() {
		var opts gcsblob.Options
		var creds *google.Credentials
		if os.Getenv("STORAGE_EMULATOR_HOST") != "" {
			creds, _ = google.CredentialsFromJSON(ctx, []byte(`{"type": "service_account", "project_id": "my-project-id"}`))
		} else {
			var err error
			// Check if universe_domain is specified in the URL query parameters
			universeDomain := u.Query().Get("universe_domain")
			if universeDomain != "" {
				creds, err = gcp.DefaultCredentialsWithParams(ctx, google.CredentialsParams{
					UniverseDomain: universeDomain,
				})
			} else {
				creds, err = gcp.DefaultCredentials(ctx)
			}
			if err != nil {
				fmt.Printf("Warning: unable to load GCP Default Credentials: %v", err)
				// Use empty credentials, in case the user isn't going to actually use
				// them; e.g., getting signed URLs with GoogleAccessID=-.
				creds, _ = google.CredentialsFromJSON(ctx, []byte(`{"type": "service_account"}`))
			}

			// Populate default values from credentials files, where available.
			opts.GoogleAccessID, opts.PrivateKey = readDefaultCredentials(creds.JSON)

			ud, err := creds.GetUniverseDomain()
			if err != nil {
				fmt.Printf("Warning: unable to load GCP Universe Domain: %v", err)
			} else if ud != "" {
				opts.ClientOptions = append(opts.ClientOptions, option.WithUniverseDomain(ud))
			}

			// ... else, on GCE, at least get the instance's main service account.
			if opts.GoogleAccessID == "" && metadata.OnGCE() {
				mc := metadata.NewClient(nil)
				opts.GoogleAccessID, _ = mc.Email("")
			}
		}

		// Provide a default factory for SignBytes for environments without a private key.
		if len(opts.PrivateKey) <= 0 && opts.GoogleAccessID != "" {
			iam := new(credentialsClient)
			// We cannot hold onto the first context: it might've been cancelled already.
			ctx := context.Background()
			opts.MakeSignBytes = iam.CreateMakeSignBytesWith(ctx, opts.GoogleAccessID)
		}

		//!!! difference with upstream client
		client, err := gcp.NewHTTPClient(&identityRoundTripper{
			base: gcp.DefaultTransport(),
		}, creds.TokenSource)
		if err != nil {
			o.err = err
			return
		}
		o.opener = &identityURLOpener{Client: client, Options: opts}
	})
	if o.err != nil {
		return nil, fmt.Errorf("open bucket %v: %w", u, o.err)
	}
	return o.opener.OpenBucketURL(ctx, u)
}

// credentialsClient wraps the IAM Credentials API client for a lazy initialization
// and expresses it in the reduced format expected by SignBytes.
// See https://cloud.google.com/iam/docs/reference/credentials/rest
type credentialsClient struct {
	init sync.Once
	err  error

	// client as reduced surface of credentials.IamCredentialsClient
	// enables us to use a mock in tests.
	client interface {
		SignBlob(context.Context, *credentialspb.SignBlobRequest, ...gax.CallOption) (*credentialspb.SignBlobResponse, error)
	}
}

// CreateMakeSignBytesWith produces a MakeSignBytes variant from an expanded parameter set.
// It essentially adapts a remote call to the IAM Credentials API
// to the function signature expected by storage.SignedURLOptions.SignBytes.
func (c *credentialsClient) CreateMakeSignBytesWith(lifetimeCtx context.Context, googleAccessID string) func(context.Context) gcsblob.SignBytesFunc {
	return func(requestCtx context.Context) gcsblob.SignBytesFunc {
		c.init.Do(func() {
			if c.client != nil {
				// Set previously, likely to a mock implementation for tests.
				return
			}
			c.client, c.err = credentials.NewIamCredentialsClient(lifetimeCtx)
		})

		return func(p []byte) ([]byte, error) {
			if c.err != nil {
				return nil, c.err
			}

			resp, err := c.client.SignBlob(
				requestCtx,
				&credentialspb.SignBlobRequest{
					Name:    googleAccessID,
					Payload: p,
				})
			if err != nil {
				return nil, err
			}
			return resp.GetSignedBlob(), nil
		}
	}
}

// readDefaultCredentials gets the field values from the supplied JSON data.
// For its possible formats please see
// https://cloud.google.com/iam/docs/creating-managing-service-account-keys#iam-service-account-keys-create-go
//
// Use "golang.org/x/oauth2/google".DefaultCredentials.JSON to get
// the contents of the preferred credential file.
//
// Returns null-values for fields that have not been obtained.
func readDefaultCredentials(credFileAsJSON []byte) (AccessID string, PrivateKey []byte) {
	// For example, a credentials file as generated for service accounts through the web console.
	var contentVariantA struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(credFileAsJSON, &contentVariantA); err == nil {
		AccessID = contentVariantA.ClientEmail
		PrivateKey = []byte(contentVariantA.PrivateKey)
	}
	if AccessID != "" {
		return AccessID, PrivateKey
	}

	// If obtained through the REST API.
	var contentVariantB struct {
		Name           string `json:"name"`
		PrivateKeyData string `json:"privateKeyData"`
	}
	if err := json.Unmarshal(credFileAsJSON, &contentVariantB); err == nil {
		nextFieldIsAccessID := false
		for s := range strings.SplitSeq(contentVariantB.Name, "/") {
			if nextFieldIsAccessID {
				AccessID = s
				break
			}
			nextFieldIsAccessID = s == "serviceAccounts"
		}
		PrivateKey = []byte(contentVariantB.PrivateKeyData)
	}

	return AccessID, PrivateKey
}
