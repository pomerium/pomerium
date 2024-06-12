package k8s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers/k8s/rest"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

func init() {
	writers.RegisterBuilder("secret", newInClusterSecretWriter)
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

func newSecretWriterForConfig(uri *url.URL, config *rest.Config) (writers.ConfigWriter, error) {
	parts := strings.SplitN(path.Join(uri.Host, uri.Path), "/", 3)
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("invalid secret uri %q, expecting format \"secret://namespace/name/key\"", uri.String())
	} else if parts[0] == "" {
		return nil, fmt.Errorf(`invalid secret uri %q (did you mean "secret:/%s"?)`, uri.String(), uri.Path)
	}
	u, err := url.Parse(config.Host)
	if err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = config.TLSClientConfig

	client := &http.Client{
		Transport: &roundTripper{
			bearerToken: config.BearerToken,
			base:        transport,
		},
	}

	return &secretWriter{
		client:       client,
		apiserverURL: u,
		namespace:    parts[0],
		name:         parts[1],
		key:          parts[2],
	}, nil
}

func newInClusterSecretWriter(uri *url.URL) (writers.ConfigWriter, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return newSecretWriterForConfig(uri, config)
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

type roundTripper struct {
	base        http.RoundTripper
	bearerToken string
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", rt.bearerToken))
	}
	return rt.base.RoundTrip(req)
}
