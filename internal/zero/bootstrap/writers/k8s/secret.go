package k8s

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

func init() {
	writers.RegisterBuilder("secret", func(uri *url.URL) (writers.ConfigWriter, error) {
		return newSecretWriter(uri)
	})
}

type secretWriter struct {
	client       *http.Client
	apiserverURL *url.URL
	namespace    string
	name         string
	key          string
}

func newSecretWriter(uri *url.URL) (*secretWriter, error) {
	client, apiserverURL, err := inClusterConfig()
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(path.Join(uri.Host, uri.Path), "/", 3)
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("invalid secret uri %q, expecting format \"secret://namespace/name/key\"", uri.String())
	} else if parts[0] == "" {
		return nil, fmt.Errorf(`invalid secret uri %q (did you mean "secret:/%s"?)`, uri.String(), uri.Path)
	}
	return &secretWriter{
		client:       client,
		apiserverURL: apiserverURL,
		namespace:    parts[0],
		name:         parts[1],
		key:          parts[2],
	}, nil
}

// WriteConfig implements ConfigWriter.
func (w *secretWriter) WriteConfig(ctx context.Context, src *cluster_api.BootstrapConfig, cipher cipher.AEAD) error {
	u := w.apiserverURL.ResolveReference(&url.URL{
		Path: path.Join("/api/v1/namespaces", w.namespace, "secrets", w.name),
		RawQuery: url.Values{
			"fieldManager": {"pomerium-zero"},
			"force":        {"true"},
		}.Encode(),
	})
	plaintext, err := json.Marshal(src)
	if err != nil {
		return err
	}
	ciphertext := cryptutil.Encrypt(cipher, plaintext, nil)
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

	patch := fmt.Sprintf(`---
apiVersion: v1
kind: Secret
metadata:
  name: %q
  namespace: %q
data:
  %q: %q
`, w.name, w.namespace, w.key, encodedCiphertext)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u.String(), strings.NewReader(patch))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/apply-patch+yaml")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusForbidden:
		if resp.Header.Get("Content-Type") == "application/json" {
			// log the detailed status message if available
			status, err := io.ReadAll(resp.Body)
			if err != nil && len(status) > 0 {
				log.Ctx(ctx).Error().
					RawJSON("response", status).
					Msg("forbidden")
			}
		}
	}
	return fmt.Errorf("unexpected status: %s", resp.Status)
}

var _ writers.ConfigWriter = (*secretWriter)(nil)

// code below adapted from k8s.io/client-go/rest/config.go

var ErrNotInCluster = errors.New("unable to load in-cluster configuration, KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be defined")

var (
	tokenFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec
	rootCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

func inClusterConfig() (*http.Client, *url.URL, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return nil, nil, ErrNotInCluster
	}

	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, nil, err
	}

	cacert, err := os.ReadFile(rootCAFile)
	if err != nil {
		return nil, nil, err
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cacert)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}

	client := &http.Client{
		Transport: &roundTripper{
			bearerToken: token,
			base:        transport,
		},
	}

	apiserverURL := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, port),
	}

	return client, apiserverURL, nil
}

type roundTripper struct {
	base        http.RoundTripper
	bearerToken []byte
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", rt.bearerToken))
	}
	return rt.base.RoundTrip(req)
}
