package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
	"github.com/square/go-jose/jwt"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sync/errgroup"
)

func init() {
	kubernetesCmd.AddCommand(kubernetesExecCredentialCmd)
	rootCmd.AddCommand(kubernetesCmd)
}

var kubernetesCmd = &cobra.Command{
	Use: "kubernetes",
}

var kubernetesExecCredentialCmd = &cobra.Command{
	Use: "exec-credential",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !terminal.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("only interactive sessions are supported")
		}

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

		li, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fatalf("failed to start listener: %v", err)
		}
		defer li.Close()

		incomingJWT := make(chan string)

		eg, ctx := errgroup.WithContext(context.Background())
		eg.Go(func() error {
			return runHTTPServer(ctx, li, incomingJWT)
		})
		eg.Go(func() error {
			return runOpenBrowser(ctx, li, serverURL)
		})
		eg.Go(func() error {
			return runHandleJWT(ctx, serverURL, incomingJWT)
		})
		err = eg.Wait()
		if err != nil {
			fatalf("%s", err)
		}

		return nil
	},
}

func runHTTPServer(ctx context.Context, li net.Listener, incomingJWT chan string) error {
	var srv *http.Server
	srv = &http.Server{
		BaseContext: func(li net.Listener) context.Context {
			return ctx
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwt := r.FormValue("pomerium_jwt")
			if jwt == "" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			incomingJWT <- jwt

			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "login complete, you may close this page")

			go func() { _ = srv.Shutdown(ctx) }()
		}),
	}
	err := srv.Serve(li)
	if err == http.ErrServerClosed {
		err = nil
	}
	return err
}

func runOpenBrowser(ctx context.Context, li net.Listener, serverURL *url.URL) error {
	dst := serverURL.ResolveReference(&url.URL{
		Path: "/.pomerium/api/v1/login",
		RawQuery: url.Values{
			"pomerium_redirect_uri": {fmt.Sprintf("http://%s", li.Addr().String())},
		}.Encode(),
	})

	req, err := http.NewRequestWithContext(ctx, "GET", dst.String(), nil)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get login url: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return fmt.Errorf("failed to get login url: %s", res.Status)
	}

	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read login url: %w", err)
	}

	return open.Run(string(bs))
}

func runHandleJWT(ctx context.Context, serverURL *url.URL, incomingJWT chan string) error {
	var rawjwt string
	select {
	case <-ctx.Done():
		return ctx.Err()
	case rawjwt = <-incomingJWT:
	}

	creds, err := parseToken(rawjwt)
	if err != nil {
		return err
	}

	saveCachedCredential(serverURL.String(), creds)
	printCreds(creds)

	return nil
}

func parseToken(rawjwt string) (*ExecCredential, error) {
	tok, err := jwt.ParseSigned(rawjwt)
	if err != nil {
		return nil, err
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	err = tok.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Unix(claims.Exp, 0)
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Minute)
	}

	return &ExecCredential{
		TypeMeta: TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Kind:       "ExecCredential",
		},
		Status: &ExecCredentialStatus{
			ExpirationTimestamp: time.Now().Add(time.Second * 10),
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
