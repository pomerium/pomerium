package k8s

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers/k8s/rest"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

func TestSecretWriter(t *testing.T) {
	requests := make(chan *http.Request, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := r.Clone(t.Context())
		contents, _ := io.ReadAll(r.Body)
		req.Body = io.NopCloser(bytes.NewReader(contents))
		requests <- req
		w.WriteHeader(http.StatusOK)
	}))

	server.StartTLS()
	defer server.Close()

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())

	restConfig := &rest.Config{
		Host: server.URL,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		},
		BearerToken: "token",
	}

	// replace the default in-cluster builder with one that uses the test server
	writers.RegisterBuilder("secret", func(uri *url.URL) (writers.ConfigWriter, error) {
		return newSecretWriterForConfig(uri, restConfig)
	})

	t.Run("Writer", func(t *testing.T) {
		writer, err := writers.NewForURI("secret://pomerium/bootstrap/bootstrap.dat")
		require.NoError(t, err)
		cipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
		require.NoError(t, err)

		txt := "test"
		src := cluster_api.BootstrapConfig{
			DatabrokerStorageConnection: &txt,
			PseudonymizationKey:         []byte{1, 2, 3},
		}

		writer = writer.WithOptions(writers.ConfigWriterOptions{
			Cipher: cipher,
		})

		require.NoError(t, bootstrap.SaveBootstrapConfig(t.Context(), writer, &src))

		r := <-requests
		assert.Equal(t, "PATCH", r.Method)
		assert.Equal(t, "application/apply-patch+yaml", r.Header.Get("Content-Type"))
		assert.Equal(t, "/api/v1/namespaces/pomerium/secrets/bootstrap?fieldManager=pomerium-zero&force=true", r.RequestURI)

		unstructured := make(map[string]any)
		require.NoError(t, yaml.NewDecoder(r.Body).Decode(&unstructured))

		// decrypt data["bootstrap.dat"] and replace it with the plaintext, so
		// it can be compared (the ciphertext will be different each time)
		encoded, err := base64.StdEncoding.DecodeString(unstructured["data"].(map[string]any)["bootstrap.dat"].(string))
		require.NoError(t, err)
		plaintext, err := cryptutil.Decrypt(cipher, encoded, nil)
		require.NoError(t, err)
		unstructured["data"].(map[string]any)["bootstrap.dat"] = string(plaintext)

		require.Equal(t, map[string]any{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]any{
				"name":      "bootstrap",
				"namespace": "pomerium",
			},
			"data": map[string]any{
				"bootstrap.dat": mustJSON(map[string]any{
					"clusterId":                   "",
					"databrokerStorageConnection": "test",
					"organizationId":              "",
					"pseudonymizationKey":         "AQID",
					"sharedSecret":                nil,
				}),
			},
		}, unstructured)
	})

	t.Run("NewForURI", func(t *testing.T) {
		for _, tc := range []struct {
			uris []string
			errf string
		}{
			{
				uris: []string{
					"secret://namespace",
					"secret://namespace/name",
					"secret:///",
					"secret:////",
					"secret://namespace//",
					"secret://namespace/name/",
				},
				errf: `invalid secret uri "%s", expecting format "secret://namespace/name/key"`,
			},
			{
				uris: []string{"secret:///namespace/name/key"},
				errf: `invalid secret uri "%s" (did you mean "secret://namespace/name/key"?)`,
			},
			{
				uris: []string{"secret:///namespace/name/key/with/slashes"},
				errf: `invalid secret uri "%s" (did you mean "secret://namespace/name/key/with/slashes"?)`,
			},
			{
				uris: []string{
					"secret://namespace/name/key",
					"secret://namespace/name/key/with/slashes",
					"secret://namespace/name/key.with.dots",
					"secret://namespace/name/key_with_underscores",
					"secret://namespace/name/key-with-dashes",
					"secret://namespace-with-dashes/name-with-dashes/key-with-dashes",
					"secret://namespace_with_underscores/name_with_underscores/key_with_underscores",
					"secret://namespace.with.dots/name.with.dots/key.with.dots",
					"secret://namespace-with-dashes/name/key/with/slashes",
					"secret://namespace_with_underscores/name.with.dots/_key/with_/_slashes_and_underscores",
				},
			},
		} {
			for _, uri := range tc.uris {
				w, err := writers.NewForURI(uri)
				if tc.errf == "" {
					assert.NoError(t, err)
					assert.NotNil(t, w)
				} else {
					assert.EqualError(t, err, fmt.Sprintf(tc.errf, uri))
					assert.Nil(t, w)
				}
			}
		}
	})
}

func mustJSON(v any) string {
	bs, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(bs)
}
