package k8s

import (
	"bytes"
	"context"
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
	"gopkg.in/yaml.v3"
)

func init() {
	writers.RegisterBuilder("secret", newSecretWriter)
}

type secretWriter struct {
	opts         writers.ConfigWriterOptions
	client       *http.Client
	apiserverURL *url.URL
	namespace    string
	name         string
	key          string
}

// WithOptions implements writers.ConfigWriter.
func (w *secretWriter) WithOptions(opts writers.ConfigWriterOptions) writers.ConfigWriter {
	clone := *w
	clone.opts = opts
	return &clone
}

func newSecretWriter(uri *url.URL) (writers.ConfigWriter, error) {
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
func (w *secretWriter) WriteConfig(ctx context.Context, src *cluster_api.BootstrapConfig) error {
	u := w.apiserverURL.ResolveReference(&url.URL{
		Path: path.Join("/api/v1/namespaces", w.namespace, "secrets", w.name),
		RawQuery: url.Values{
			"fieldManager": {"pomerium-zero"},
			"force":        {"true"},
		}.Encode(),
	})
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}

	if w.opts.Cipher != nil {
		data = cryptutil.Encrypt(w.opts.Cipher, data, nil)
	}
	encodedData := base64.StdEncoding.EncodeToString(data)

	patch, _ := yaml.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      w.name,
			"namespace": w.namespace,
		},
		"data": map[string]string{
			w.key: encodedData,
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u.String(), bytes.NewReader(patch))
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
			if err != nil {
				break
			}
			var buf bytes.Buffer
			err = json.Compact(&buf, status)
			if err != nil {
				break
			}
			log.Ctx(ctx).Error().
				RawJSON("response", buf.Bytes()).
				Msgf("%s %s: %s", req.Method, req.URL, resp.Status)
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
