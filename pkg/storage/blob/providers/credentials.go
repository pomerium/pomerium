package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/gcp"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/credentials"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type CredentialsLoader interface {
	Name() string
	GCPCredentialLoader
}

type GCPCredentialLoader interface {
	LoadGCPCredentials(ctx context.Context, u *url.URL) (creds *google.Credentials, opts gcsblob.Options, err error)
}

type AzureCredentialLoader interface {
	// TODO
}

type AWSCredentialLoader interface {
	// TODO
}

type DefaultCredentialLoader struct{}

// https://github.com/google/go-cloud/blob/7eadd65be3cf297188f2781d99823bb135fec385/blob/gcsblob/gcsblob.go#L102-L143
// readDefaultCredentials gets the field values from the supplied JSON data.
// For its possible formats please see
// https://cloud.google.com/iam/docs/creating-managing-service-account-keys#iam-service-account-keys-create-go
//
// Use "golang.org/x/oauth2/google".DefaultCredentials.JSON to get
// the contents of the preferred credential file.
//
// Returns null-values for fields that have not been obtained.
func readDefaultGCPCredentials(credFileAsJSON []byte) (AccessID string, PrivateKey []byte) {
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

// Adapation of:
// https://github.com/google/go-cloud/blob/7eadd65be3cf297188f2781d99823bb135fec385/blob/gcsblob/gcsblob.go#L160-L207
func (d *DefaultCredentialLoader) LoadGCPCredentials(ctx context.Context, u *url.URL) (creds *google.Credentials, opts gcsblob.Options, err error) {
	universeDomain := u.Query().Get("universe_domain")
	if universeDomain != "" {
		creds, err = gcp.DefaultCredentialsWithParams(ctx, google.CredentialsParams{
			UniverseDomain: universeDomain,
		})
	} else {
		creds, err = gcp.DefaultCredentials(ctx)
	}
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("unable to load GCP Default Credentials, falling back to service account")
		// Use empty credentials, in case the user isn't going to actually use
		// them; e.g., getting signed URLs with GoogleAccessID=-.
		creds, _ = google.CredentialsFromJSON(ctx, []byte(`{"type": "service_account"}`))
	}

	// Populate default values from credentials files, where available.
	opts.GoogleAccessID, opts.PrivateKey = readDefaultGCPCredentials(creds.JSON)

	ud, err := creds.GetUniverseDomain()
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("unable to load GCP Universe Domain")
	} else if ud != "" {
		opts.ClientOptions = append(opts.ClientOptions, option.WithUniverseDomain(ud))
	}

	// ... else, on GCE, at least get the instance's main service account.
	if opts.GoogleAccessID == "" && metadata.OnGCE() {
		mc := metadata.NewClient(nil)
		opts.GoogleAccessID, _ = mc.Email("")
	}

	// Provide a default factory for SignBytes for environments without a private key.
	if len(opts.PrivateKey) <= 0 && opts.GoogleAccessID != "" {
		iam := new(credentialsClient)
		// We cannot hold onto the first context: it might've been cancelled already.
		ctx := context.Background()
		opts.MakeSignBytes = iam.CreateMakeSignBytesWith(ctx, opts.GoogleAccessID)
	}
	return creds, opts, err
}

type DatabrokerCredentialLoader struct {
	clientB databroker.ClientGetter
}

func (d *DatabrokerCredentialLoader) LoadGCPCredentials(ctx context.Context, u *url.URL) (creds *google.Credentials, opts gcsblob.Options, err error) {
	client := d.clientB.GetDataBrokerServiceClient()
	credentialData := new(credentials.BlobProviderCredential)
	resp, err := client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(credentialData),
		Id:   "blob",
	})
	if err != nil {
		return creds, opts, err
	}
	if err = resp.GetRecord().GetData().UnmarshalTo(credentialData); err != nil {
		return creds, opts, err
	}

	if credentialData.GetGcp() == nil {
		err = fmt.Errorf("wrong credential type, expected GCP")
		return creds, opts, err
	}
	credType := google.CredentialsType(credentialData.GetGcp().GetCredentialType())

	universeDomain := u.Query().Get("universe_domain")
	if universeDomain != "" {
		creds, err = google.CredentialsFromJSONWithTypeAndParams(ctx, credentialData.GetGcp().GetData(), credType, google.CredentialsParams{
			UniverseDomain: universeDomain,
		})
	} else {
		creds, err = google.CredentialsFromJSONWithType(ctx, credentialData.GetGcp().GetData(), credType)
	}
	if err != nil {
		return creds, opts, err
	}
	ud, err := creds.GetUniverseDomain()
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("unable to load GCP Universe Domain")
	} else if ud != "" {
		opts.ClientOptions = append(opts.ClientOptions, option.WithUniverseDomain(ud))
	}

	// ... else, on GCE, at least get the instance's main service account.
	if opts.GoogleAccessID == "" && metadata.OnGCE() {
		mc := metadata.NewClient(nil)
		opts.GoogleAccessID, _ = mc.Email("")
	}

	// Provide a default factory for SignBytes for environments without a private key.
	if len(opts.PrivateKey) <= 0 && opts.GoogleAccessID != "" {
		iam := new(credentialsClient)
		// We cannot hold onto the first context: it might've been cancelled already.
		ctx := context.Background()
		opts.MakeSignBytes = iam.CreateMakeSignBytesWith(ctx, opts.GoogleAccessID)
	}
	return creds, opts, err
}
