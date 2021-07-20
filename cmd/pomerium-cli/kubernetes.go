package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/spf13/cobra"

	"github.com/pomerium/pomerium/internal/authclient"
)

func init() {
	addTLSFlags(kubernetesExecCredentialCmd)
	kubernetesCmd.AddCommand(kubernetesExecCredentialCmd)
	kubernetesCmd.AddCommand(kubernetesFlushCredentialsCmd)
	rootCmd.AddCommand(kubernetesCmd)
}

var kubernetesCmd = &cobra.Command{
	Use: "k8s",
}

var kubernetesFlushCredentialsCmd = &cobra.Command{
	Use: "flush-credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			clearAllCachedCredentials()
		} else {
			clearCachedCredential(args[0])
		}
		return nil
	},
}

var kubernetesExecCredentialCmd = &cobra.Command{
	Use: "exec-credential",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("server url is required")
		}

		serverURL, err := url.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid server url: %v", err)
		}

		creds := loadCachedCredential(serverURL.String())
		if creds != nil {
			printCreds(creds)
			return nil
		}

		var tlsConfig *tls.Config
		if serverURL.Scheme == "https" {
			tlsConfig = getTLSConfig()
		}

		ac := authclient.New(authclient.WithTLSConfig(tlsConfig))
		rawJWT, err := ac.GetJWT(context.Background(), serverURL)
		if err != nil {
			fatalf("%s", err)
		}

		creds, err = parseToken(rawJWT)
		if err != nil {
			fatalf("%s", err)
		}

		saveCachedCredential(serverURL.String(), creds)
		printCreds(creds)

		return nil
	},
}

func parseToken(rawjwt string) (*ExecCredential, error) {
	tok, err := jose.ParseSigned(rawjwt)
	if err != nil {
		return nil, err
	}

	var claims struct {
		Expiry int64 `json:"exp"`
	}
	err = json.Unmarshal(tok.UnsafePayloadWithoutVerification(), &claims)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Unix(claims.Expiry, 0)
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Hour)
	}

	return &ExecCredential{
		TypeMeta: TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Kind:       "ExecCredential",
		},
		Status: &ExecCredentialStatus{
			ExpirationTimestamp: expiresAt,
			Token:               "Pomerium-" + rawjwt,
		},
	}, nil
}

func printCreds(creds *ExecCredential) {
	bs, err := json.Marshal(creds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode credentials: %v\n", err)
	}
	fmt.Println(string(bs))
}

// TypeMeta describes an individual object in an API response or request
// with strings representing the type of the object and its API schema version.
// Structures that are versioned or persisted should inline TypeMeta.
//
// +k8s:deepcopy-gen=false
type TypeMeta struct {
	// Kind is a string value representing the REST resource this object represents.
	// Servers may infer this from the endpoint the client submits requests to.
	// Cannot be updated.
	// In CamelCase.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
	// +optional
	Kind string `json:"kind,omitempty" protobuf:"bytes,1,opt,name=kind"`

	// APIVersion defines the versioned schema of this representation of an object.
	// Servers should convert recognized schemas to the latest internal value, and
	// may reject unrecognized values.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources
	// +optional
	APIVersion string `json:"apiVersion,omitempty" protobuf:"bytes,2,opt,name=apiVersion"`
}

// ExecCredential is used by exec-based plugins to communicate credentials to
// HTTP transports.
type ExecCredential struct {
	TypeMeta `json:",inline"`

	// Status is filled in by the plugin and holds the credentials that the transport
	// should use to contact the API.
	// +optional
	Status *ExecCredentialStatus `json:"status,omitempty"`
}

// ExecCredentialStatus holds credentials for the transport to use.
//
// Token and ClientKeyData are sensitive fields. This data should only be
// transmitted in-memory between client and exec plugin process. Exec plugin
// itself should at least be protected via file permissions.
type ExecCredentialStatus struct {
	// ExpirationTimestamp indicates a time when the provided credentials expire.
	// +optional
	ExpirationTimestamp time.Time `json:"expirationTimestamp,omitempty"`
	// Token is a bearer token used by the client for request authentication.
	Token string `json:"token,omitempty"`
	// PEM-encoded client TLS certificates (including intermediates, if any).
	ClientCertificateData string `json:"clientCertificateData,omitempty"`
	// PEM-encoded private key for the above certificate.
	ClientKeyData string `json:"clientKeyData,omitempty"`
}
