package config_test

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/derivecert"
	"github.com/pomerium/pomerium/pkg/hpke"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestGenerateCatchAllCertificate(t *testing.T) {
	expected := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILl9Nj1pmMzK/dHZ1yZcF1aPsCL0iqDsyHvIAyr4JNX+oAoGCCqGSM49
AwEHoUQDQgAEpDspy8qOG7ARSokzfO86qBnuMetrXUWhPoOU68aqr/KlsIW+KvX1
FiPqTUIoAXth7BiRbJ3gNjNEtdUV1Rtn3w==
-----END EC PRIVATE KEY-----
`
	cfg := config.New(&config.Options{
		SharedKey: base64.StdEncoding.EncodeToString([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")),
	})
	cert, err := cfg.GenerateCatchAllCertificate()
	require.NoError(t, err)
	key, err := cryptutil.EncodePrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	assert.Equal(t, expected, string(key))

	cfg.Options.DeriveInternalDomainCert = new("example.com")
	cert, err = cfg.GenerateCatchAllCertificate()
	require.NoError(t, err)
	key, err = cryptutil.EncodePrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	assert.Equal(t, expected, string(key))
}

func TestGenerated(t *testing.T) {
	t.Parallel()
	t.Run("json", func(t *testing.T) {
		t.Parallel()
		var dst config.GlobalOptions
		require.NoError(t, json.Unmarshal([]byte(`{"allow_upgrades":["x","y","z"]}`), &dst))
		assert.Equal(t, config.GlobalOptions{
			AllowUpgrades: nullable.From([]string{"x", "y", "z"}),
		}, dst)
		require.NoError(t, json.Unmarshal([]byte(`{}`), &dst))
		assert.Equal(t, config.GlobalOptions{
			AllowUpgrades: nullable.From([]string{"x", "y", "z"}),
		}, dst, "should preserve existing value")
	})
	t.Run("viper", func(t *testing.T) {
		t.Parallel()
		fp := filepath.Join(t.TempDir(), "config.json")
		require.NoError(t, os.WriteFile(fp, []byte(`{"allow_upgrades":["x","y","z"]}`), 0o600))
		v := viper.New()
		v.AddConfigPath(filepath.Dir(fp))
		require.NoError(t, v.ReadInConfig())
		var dst config.GlobalOptions
		require.NoError(t, v.Unmarshal(&dst, config.ViperPolicyHooks))
		assert.Equal(t, config.GlobalOptions{
			AllowUpgrades: nullable.From([]string{"x", "y", "z"}),
		}, dst)
	})
	t.Run("yaml", func(t *testing.T) {
		t.Parallel()
		var dst config.GlobalOptions
		err := yaml.Unmarshal([]byte(`
allow_upgrades:
  - x
  - y
  - z
`), &dst)
		require.NoError(t, err)
		assert.Equal(t, config.GlobalOptions{
			AllowUpgrades: nullable.From([]string{"x", "y", "z"}),
		}, dst)
	})
}

func TestHostedAuthenticateKeyFetcher(t *testing.T) {
	// not parallel: replaces http.DefaultTransport

	sharedKey := cryptutil.NewKey()
	ca, err := derivecert.NewCA(sharedKey)
	require.NoError(t, err)
	caPEM, err := ca.PEM()
	require.NoError(t, err)
	serverPEM, err := ca.NewServerCert([]string{"authenticate.pomerium.app"})
	require.NoError(t, err)
	serverCert, err := serverPEM.TLS()
	require.NoError(t, err)

	hpkeKey, err := hpke.GeneratePrivateKey()
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(hpkeKey.PublicKey().Bytes())
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	proxyURL := newTunnelProxy(t, srv.Listener.Addr().String())
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	transport := originalTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	http.DefaultTransport = transport

	fetch := func(t *testing.T, cfg *config.Config) (*hpke.PublicKey, error) {
		t.Helper()
		fetcher, err := cfg.GetAuthenticateKeyFetcher()
		require.NoError(t, err)
		return fetcher.FetchPublicKey(t.Context())
	}

	t.Run("untrusted certificate authority", func(t *testing.T) {
		_, err := fetch(t, config.New(&config.Options{}))
		var verifyErr *tls.CertificateVerificationError
		assert.ErrorAs(t, err, &verifyErr)
	})
	t.Run("derived certificate authority", func(t *testing.T) {
		cfg := config.New(&config.Options{
			SharedKey:                base64.StdEncoding.EncodeToString(sharedKey),
			DeriveInternalDomainCert: new("internal.example.com"),
		})
		cfg.DerivedCAPEM = caPEM.Cert
		_, err := fetch(t, cfg)
		var verifyErr *tls.CertificateVerificationError
		assert.ErrorAs(t, err, &verifyErr)
	})
	t.Run("configured certificate authority", func(t *testing.T) {
		key, err := fetch(t, config.New(&config.Options{
			CA: base64.StdEncoding.EncodeToString(caPEM.Cert),
		}))
		require.NoError(t, err)
		assert.Equal(t, hpkeKey.PublicKey().Bytes(), key.Bytes())
	})
	t.Run("configured certificate authority file", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "ca.pem")
		require.NoError(t, os.WriteFile(caFile, caPEM.Cert, 0o600))
		key, err := fetch(t, config.New(&config.Options{CAFile: caFile}))
		require.NoError(t, err)
		assert.Equal(t, hpkeKey.PublicKey().Bytes(), key.Bytes())
	})
	t.Run("invalid certificate authority", func(t *testing.T) {
		_, err := fetch(t, config.New(&config.Options{
			CA: base64.StdEncoding.EncodeToString([]byte("invalid")),
		}))
		var verifyErr *tls.CertificateVerificationError
		assert.ErrorAs(t, err, &verifyErr)
	})
}

// newTunnelProxy starts an HTTP proxy that tunnels every CONNECT request to
// target.
func newTunnelProxy(t *testing.T, target string) *url.URL {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstream, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		client, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		go func() {
			_, _ = io.Copy(upstream, client)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(client, upstream)
	}))
	t.Cleanup(proxy.Close)
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	return proxyURL
}
