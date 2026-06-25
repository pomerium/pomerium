package providers

// Copyright 2018 The Go Cloud Development Kit Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// https://github.com/google/go-cloud/blob/7eadd65be3cf297188f2781d99823bb135fec385/blob/azureblob/azureblob.go#L324-L401
// differences from upstream are labelled with !!

import (
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"gocloud.dev/blob/azureblob"
)

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
	azClientOpts.PerCallPolicies = []policy.Policy{azureAuditHeaderPolicy{}} // !! pomerium injected middleware
	azClientOpts.Telemetry = policy.TelemetryOptions{
		ApplicationID: "", // !! pomerium sets user agent headers in middleware
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
