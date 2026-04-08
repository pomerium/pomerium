package providers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"gocloud.dev/blob"
	"gocloud.dev/blob/azureblob"
)

var azureIdentityOpener = &lazyOpener{}

// URLOpener opens Azure URLs like "azblob://mybucket".
//
// The URL host is used as the bucket name.
//
// The following query options are supported:
//   - domain: Overrides Options.StorageDomain.
//   - protocol: Overrides Options.Protocol.
//   - cdn: Overrides Options.IsCDN.
//   - localemu: Overrides Options.IsLocalEmulator.
type URLOpener struct {
	// MakeClient must be set to a non-nil value.
	MakeClient func(svcURL azureblob.ServiceURL, containerName azureblob.ContainerName) (*container.Client, error)

	// ServiceURLOptions specifies default options for generating the service URL.
	// Some options can be overridden in the URL as described above.
	ServiceURLOptions azureblob.ServiceURLOptions

	// Options specifies the options to pass to OpenBucket.
	Options azureblob.Options
}

// withOverrides returns o with overrides from urlValues.
// See URLOpener for supported overrides.
func withOverrides(o *azureblob.ServiceURLOptions, urlValues url.Values) (*azureblob.ServiceURLOptions, error) {
	retval := *o
	for param, values := range urlValues {
		if len(values) > 1 {
			return nil, fmt.Errorf("multiple values of %v not allowed", param)
		}
		value := values[0]
		switch param {
		case "domain":
			retval.StorageDomain = value
		case "protocol":
			retval.Protocol = value
		case "cdn":
			isCDN, err := strconv.ParseBool(value)
			if err != nil {
				return nil, err
			}
			retval.IsCDN = isCDN
		case "localemu":
			isLocalEmulator, err := strconv.ParseBool(value)
			if err != nil {
				return nil, err
			}
			retval.IsLocalEmulator = isLocalEmulator
		case "storage_account":
			retval.AccountName = value
		default:
			return nil, fmt.Errorf("unknown query parameter %q", param)
		}
	}
	return &retval, nil
}

// OpenBucketURL opens a blob.Bucket based on u.
func (o *URLOpener) OpenBucketURL(ctx context.Context, u *url.URL) (*blob.Bucket, error) {
	opts, err := withOverrides(&o.ServiceURLOptions, u.Query())
	if err != nil {
		return nil, err
	}
	svcURL, err := azureblob.NewServiceURL(opts)
	if err != nil {
		return nil, err
	}
	client, err := o.MakeClient(svcURL, azureblob.ContainerName(u.Host))
	if err != nil {
		return nil, err
	}
	return azureblob.OpenBucket(ctx, client, &o.Options)
}

// --
// lazyOpener obtains credentials and creates a client on the first call to OpenBucketURL.
type lazyOpener struct {
	init   sync.Once
	opener *URLOpener
}

func (o *lazyOpener) OpenBucketURL(ctx context.Context, u *url.URL) (*blob.Bucket, error) {
	o.init.Do(func() {
		credInfo := newCredInfoFromEnv()
		opts := azureblob.NewDefaultServiceURLOptions()
		o.opener = &URLOpener{
			MakeClient:        credInfo.NewClient,
			ServiceURLOptions: *opts,
		}
	})
	return o.opener.OpenBucketURL(ctx, u)
}

type credTypeEnumT int

const (
	credTypeDefault credTypeEnumT = iota
	credTypeSharedKey
	credTypeSASViaNone
	credTypeConnectionString
)

type credInfoT struct {
	CredType credTypeEnumT

	// For credTypeSharedKey.
	AccountName string
	AccountKey  string

	// For credTypeConnectionString
	ConnectionString string
}

func newCredInfoFromEnv() *credInfoT {
	accountName := os.Getenv("AZURE_STORAGE_ACCOUNT")
	accountKey := os.Getenv("AZURE_STORAGE_KEY")
	sasToken := os.Getenv("AZURE_STORAGE_SAS_TOKEN")
	connectionString := os.Getenv("AZURE_STORAGE_CONNECTION_STRING")
	if connectionString == "" {
		connectionString = os.Getenv("AZURE_STORAGEBLOB_CONNECTIONSTRING")
	}
	credInfo := &credInfoT{
		AccountName: accountName,
	}
	if accountName != "" && accountKey != "" {
		credInfo.CredType = credTypeSharedKey
		credInfo.AccountKey = accountKey
	} else if sasToken != "" {
		credInfo.CredType = credTypeSASViaNone
	} else if connectionString != "" {
		credInfo.CredType = credTypeConnectionString
		credInfo.ConnectionString = connectionString
	} else {
		credInfo.CredType = credTypeDefault
	}
	return credInfo
}

func (i *credInfoT) NewClient(svcURL azureblob.ServiceURL, containerName azureblob.ContainerName) (*container.Client, error) {
	// Set the ApplicationID.
	azClientOpts := &container.ClientOptions{}

	// !!! difference with upstream
	azClientOpts.PerCallPolicies = []policy.Policy{&identityPolicy{}}

	azClientOpts.Telemetry = policy.TelemetryOptions{
		// !! maintains compat w/ pre-existing UserAgent headers set by the SDK
		ApplicationID: AzureUserAgentPrefix("blob"),
	}

	containerURL, err := url.JoinPath(string(svcURL), string(containerName))
	if err != nil {
		return nil, err
	}
	switch i.CredType {
	case credTypeDefault:
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed azidentity.NewDefaultAzureCredential: %w", err)
		}
		return container.NewClient(containerURL, cred, azClientOpts)
	case credTypeSharedKey:
		sharedKeyCred, err := azblob.NewSharedKeyCredential(i.AccountName, i.AccountKey)
		if err != nil {
			return nil, fmt.Errorf("failed azblob.NewSharedKeyCredential: %w", err)
		}
		return container.NewClientWithSharedKeyCredential(containerURL, sharedKeyCred, azClientOpts)
	case credTypeSASViaNone:
		return container.NewClientWithNoCredential(containerURL, azClientOpts)
	case credTypeConnectionString:
		return container.NewClientFromConnectionString(i.ConnectionString, string(containerName), azClientOpts)
	default:
		return nil, errors.New("internal error, unknown cred type")
	}
}

// AzureUserAgentPrefix returns a prefix that is used to set Azure SDK User-Agent to help with diagnostics.
func AzureUserAgentPrefix(api string) string {
	return userAgentString(api)
}

func userAgentString(api string) string {
	return fmt.Sprintf("go-cloud/%s/%s", api, versionGoCloud)
}

// !! maintains compat w/ existing UserAgent headers
var versionGoCloud = func() string {
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range info.Deps {
			if dep.Path == "gocloud.dev" {
				return dep.Version
			}
		}
	}
	return "unknown"
}()
