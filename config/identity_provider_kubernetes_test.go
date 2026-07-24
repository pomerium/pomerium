package config

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKubernetesIssuer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		issuer  string
		isK8s   bool
		apiHost string
	}{
		{"kubernetes:///", true, ""},
		{"kubernetes://", true, ""},
		{"kubernetes://10.43.0.1:443", true, "10.43.0.1:443"},
		{"https://kubernetes.default.svc.cluster.local", false, ""},
		{"http://127.0.0.1:8080", false, ""},
		{"", false, ""},
		{"not a url", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			isK8s, apiHost := parseKubernetesIssuer(tt.issuer)
			assert.Equal(t, tt.isK8s, isK8s)
			assert.Equal(t, tt.apiHost, apiHost)
		})
	}
}

func TestIdentityProvider_Validate_KubernetesIssuer(t *testing.T) {
	t.Parallel()

	valid := func() IdentityProvider {
		return IdentityProvider{
			Issuer:    "kubernetes:///",
			Audiences: []string{"pomerium"},
		}
	}

	t.Run("kubernetes:/// accepted", func(t *testing.T) {
		assert.NoError(t, valid().Validate())
	})
	t.Run("kubernetes:// accepted", func(t *testing.T) {
		ip := valid()
		ip.Issuer = "kubernetes://"
		assert.NoError(t, ip.Validate())
	})
	t.Run("empty audiences still fail-closed", func(t *testing.T) {
		ip := valid()
		ip.Audiences = nil
		assert.Error(t, ip.Validate())
	})
	t.Run("supported_algs still validated", func(t *testing.T) {
		ip := valid()
		ip.SupportedAlgs = []string{"HS256"}
		assert.Error(t, ip.Validate())
	})
	t.Run("jwks_url rejected with kubernetes issuer", func(t *testing.T) {
		// The JWKS URL is discovered in-cluster; a configured jwks_url would be
		// silently ignored, so reject the combination instead.
		ip := valid()
		ip.JWKSURL = "https://example.com/keys"
		assert.Error(t, ip.Validate())
	})
	t.Run("bogus issuer still rejected", func(t *testing.T) {
		ip := valid()
		ip.Issuer = "not a url"
		assert.Error(t, ip.Validate())
	})
}

// writeTestFile writes data to a new file under dir and returns its path.
func writeTestFile(t testing.TB, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func serverCAFile(t testing.TB, dir string, srv *httptest.Server) string {
	t.Helper()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return writeTestFile(t, dir, "ca.crt", caPEM)
}

// TestKubernetesAuthRoundTripper verifies the two properties of the in-cluster
// HTTP client: the ServiceAccount token is re-read from the file on every
// round-trip (the kubelet rotates projected tokens), and TLS is verified
// against the cluster CA from the CA file.
func TestKubernetesAuthRoundTripper(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var gotAuth []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	// Trailing newline mirrors real projected token files; it must be trimmed.
	tokenFile := writeTestFile(t, dir, "token", []byte("token-1\n"))
	caFile := serverCAFile(t, dir, srv)

	client, err := newKubernetesHTTPClient(kubernetesInClusterParams{
		apiURL:    srv.URL,
		tokenFile: tokenFile,
		caFile:    caFile,
	})
	require.NoError(t, err)

	get := func() {
		resp, err := client.Get(srv.URL)
		require.NoError(t, err)
		resp.Body.Close()
	}
	get()
	require.NoError(t, os.WriteFile(tokenFile, []byte("token-2"), 0o600))
	get()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"Bearer token-1", "Bearer token-2"}, gotAuth,
		"token must be re-read from the file on every request")

	t.Run("without the cluster CA the request fails", func(t *testing.T) {
		// The server uses a self-signed certificate, so success above proves the
		// CA file was wired into the TLS config; the default client must fail.
		_, err := http.DefaultClient.Get(srv.URL)
		require.Error(t, err)
	})

	t.Run("missing token file fails the request", func(t *testing.T) {
		client, err := newKubernetesHTTPClient(kubernetesInClusterParams{
			apiURL:    srv.URL,
			tokenFile: filepath.Join(dir, "does-not-exist"),
			caFile:    caFile,
		})
		require.NoError(t, err)
		_, err = client.Get(srv.URL)
		require.Error(t, err)
	})
}

// startKubernetesAPIStub stands up a TLS server that behaves like a modern
// Kubernetes API server for the purposes of this feature: it serves the OIDC
// discovery document (issuer = its own URL) and /openid/v1/jwks, and rejects
// any request that does not carry the expected ServiceAccount bearer token
// (as Kubernetes >= 1.34 does for anonymous JWKS requests).
func startKubernetesAPIStub(t testing.TB, acceptToken string) (srv *httptest.Server, signJWT func(claims map[string]any) string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: "ES256", Use: "sig"}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	jwk.KeyID = hex.EncodeToString(thumb)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := "https://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   issuer,
			"jwks_uri": issuer + "/openid/v1/jwks",
		})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+acceptToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	signJWT = func(claims map[string]any) string {
		tok, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)
		return tok
	}
	return srv, signJWT
}

// TestNewIdentityProviderResolver_KubernetesIssuer is the load-bearing test for
// issuer: kubernetes:///. The resolver must discover the real issuer from the
// API server's OIDC discovery document (authenticated with the ServiceAccount
// token, TLS-verified against the cluster CA), register the provider under the
// DISCOVERED issuer, and verify tokens against the authenticated JWKS fetch.
func TestNewIdentityProviderResolver_KubernetesIssuer(t *testing.T) {
	t.Parallel()

	const goodToken = "sa-token"
	srv, signJWT := startKubernetesAPIStub(t, goodToken)

	dir := t.TempDir()
	tokenFile := writeTestFile(t, dir, "token", []byte(goodToken))
	caFile := serverCAFile(t, dir, srv)
	params := kubernetesInClusterParams{apiURL: srv.URL, tokenFile: tokenFile, caFile: caFile}

	providers := map[string]IdentityProvider{
		"cluster": {
			Issuer:        "kubernetes:///",
			Audiences:     []string{"pomerium-agentic-as"},
			SupportedAlgs: []string{"ES256"},
		},
	}

	now := time.Now()
	tok := signJWT(map[string]any{
		"iss": srv.URL, // the discovered issuer, NOT kubernetes:///
		"sub": "system:serviceaccount:ns:sa",
		"aud": []string{"pomerium-agentic-as"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	})

	t.Run("discovers issuer and verifies tokens", func(t *testing.T) {
		resolver, err := NewIdentityProviderResolver(providers, nil, withKubernetesInClusterParams(params))
		require.NoError(t, err)

		name, err := resolver.ResolveName(tok)
		require.NoError(t, err)
		assert.Equal(t, "cluster", name)

		res, err := resolver.Verify(t.Context(), tok)
		require.NoError(t, err)
		assert.Equal(t, "cluster", res.ProviderName)
		assert.Equal(t, "system:serviceaccount:ns:sa", res.Claims["sub"])
	})

	t.Run("wrong ServiceAccount token fails discovery", func(t *testing.T) {
		// The API server 401s without the right bearer; if the discovery fetch
		// were unauthenticated the resolver could not be built at all.
		badParams := params
		badParams.tokenFile = writeTestFile(t, dir, "bad-token", []byte("wrong-token"))
		_, err := NewIdentityProviderResolver(providers, nil, withKubernetesInClusterParams(badParams))
		require.Error(t, err)
	})

	t.Run("duplicate resolved issuer detected", func(t *testing.T) {
		// A kubernetes:/// provider and an explicit provider resolving to the
		// same issuer would make iss-based dispatch ambiguous.
		dup := map[string]IdentityProvider{
			"cluster": providers["cluster"],
			"explicit": {
				Issuer:        srv.URL,
				Audiences:     []string{"other"},
				SupportedAlgs: []string{"ES256"},
			},
		}
		_, err := NewIdentityProviderResolver(dup, nil, withKubernetesInClusterParams(params))
		require.Error(t, err)
	})
}
