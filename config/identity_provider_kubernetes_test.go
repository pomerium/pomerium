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
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil/mockidp"
)

// testClock drives kubernetesResolveInterval without sleeping.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

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
		// The JWKS URL is the API server's own endpoint; a configured jwks_url
		// would be silently ignored, so reject the combination instead.
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

// kubernetesAPIStub is a fake API server serving /openid/v1/jwks and an OIDC
// discovery document, rejecting anything not bearing the pod's token. It serves
// the discovery document only so a test can prove we never ask for it.
type kubernetesAPIStub struct {
	srv    *httptest.Server
	signer jose.Signer

	discoveries atomic.Int64 // requests to /.well-known/openid-configuration
	// bearer is settable after construction: the pod token can only be signed
	// once the server exists, its URL being the issuer.
	bearer atomic.Value
}

func (s *kubernetesAPIStub) setBearer(tok string) { s.bearer.Store(tok) }

func (s *kubernetesAPIStub) signJWT(t testing.TB, claims map[string]any) string {
	t.Helper()
	tok, err := jwt.Signed(s.signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return tok
}

func startKubernetesAPIStub(t testing.TB) *kubernetesAPIStub {
	t.Helper()

	stub := &kubernetesAPIStub{}
	stub.bearer.Store("")

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

	stub.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			stub.discoveries.Add(1)
		}
		if r.Header.Get("Authorization") != "Bearer "+stub.bearer.Load().(string) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(stub.srv.Close)

	stub.signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	return stub
}

// kubernetesClusterFixture is the common setup for the kubernetes:/// tests: a
// stubbed API server, in-cluster parameters pointing at it, a ServiceAccount
// token for the pod itself, and a provider set plus a token to verify.
type kubernetesClusterFixture struct {
	stub      *kubernetesAPIStub
	params    kubernetesInClusterParams
	providers map[string]IdentityProvider
	token     string // a ServiceAccount token the built resolver should accept
}

func newKubernetesClusterFixture(t testing.TB) kubernetesClusterFixture {
	t.Helper()

	stub := startKubernetesAPIStub(t)
	now := time.Now()

	// Its `iss` is where the resolver gets the issuer, its raw form is the bearer
	// the API server accepts. The trailing newline mirrors a real projected token
	// file and must be trimmed by both readers.
	podToken := stub.signJWT(t, map[string]any{
		"iss": stub.srv.URL,
		"sub": "system:serviceaccount:pomerium:pomerium",
		"aud": []string{"https://kubernetes.default.svc"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	})
	stub.setBearer(podToken)

	dir := t.TempDir()
	tokenFile := writeTestFile(t, dir, "token", []byte(podToken+"\n"))

	return kubernetesClusterFixture{
		stub:   stub,
		params: kubernetesInClusterParams{apiURL: stub.srv.URL, tokenFile: tokenFile, caFile: serverCAFile(t, dir, stub.srv)},
		providers: map[string]IdentityProvider{
			"cluster": {
				Issuer:        "kubernetes:///",
				Audiences:     []string{"pomerium-agentic-as"},
				SupportedAlgs: []string{"ES256"},
			},
		},
		token: stub.signJWT(t, map[string]any{
			"iss": stub.srv.URL, // the resolved issuer, NOT kubernetes:///
			"sub": "system:serviceaccount:ns:sa",
			"aud": []string{"pomerium-agentic-as"},
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		}),
	}
}

func (f kubernetesClusterFixture) build(t testing.TB, opts ...identityProviderResolverOption) *IdentityProviderResolver {
	t.Helper()
	return newIdentityProviderResolver(t.Context(), f.providers, sharedJWKSClient{},
		append([]identityProviderResolverOption{withKubernetesInClusterParams(f.params)}, opts...)...)
}

// TestNewIdentityProviderResolver_KubernetesIssuer is the load-bearing test for
// issuer: kubernetes:///: the issuer comes from the pod's own token, and tokens
// verify against a JWKS fetched from the API server with that token as bearer.
func TestNewIdentityProviderResolver_KubernetesIssuer(t *testing.T) {
	t.Parallel()

	f := newKubernetesClusterFixture(t)

	t.Run("resolves issuer and verifies tokens", func(t *testing.T) {
		resolver := f.build(t)

		rp, err := resolver.resolveUnverified(t.Context(), f.token)
		require.NoError(t, err)
		assert.Equal(t, "cluster", rp.Name)

		res, err := resolver.Verify(t.Context(), f.token)
		require.NoError(t, err)
		assert.Equal(t, "cluster", res.ProviderName)
		assert.Equal(t, "system:serviceaccount:ns:sa", res.Claims["sub"])

		// All of that worked without the discovery document. Asserted here rather
		// than in a sibling subtest, which would pass on a counter nothing had
		// touched.
		assert.Zero(t, f.stub.discoveries.Load(),
			"the issuer comes from the pod's token, so discovery must never be requested")
	})

	t.Run("an explicit provider wins the resolved issuer", func(t *testing.T) {
		// A kubernetes:/// provider whose token names an issuer an explicit provider
		// already claims cannot be selected: dispatch matches the explicit one, whose
		// audiences (not the cluster provider's) then apply.
		dup := map[string]IdentityProvider{
			"cluster": f.providers["cluster"],
			"explicit": {
				Issuer:        f.stub.srv.URL,
				JWKSURL:       f.stub.srv.URL + kubernetesJWKSPath,
				Audiences:     []string{"pomerium-agentic-as"},
				SupportedAlgs: []string{"ES256"},
			},
		}
		resolver := newIdentityProviderResolver(t.Context(), dup, sharedJWKSClient{},
			withKubernetesInClusterParams(f.params))

		rp, err := resolver.resolveUnverified(t.Context(), f.token)
		require.NoError(t, err)
		assert.Equal(t, "explicit", rp.Name)
	})
}

// TestNewIdentityProviderResolver_KubernetesIssuerFromPodToken pins where the
// issuer comes from. The stub advertises itself in its discovery document, so a
// resolver reading that would register the stub's URL; this one must register
// what the pod token says instead.
func TestNewIdentityProviderResolver_KubernetesIssuerFromPodToken(t *testing.T) {
	t.Parallel()

	const otherIssuer = "https://issuer.elsewhere.example"

	f := newKubernetesClusterFixture(t)
	now := time.Now()
	podToken := f.stub.signJWT(t, map[string]any{
		"iss": otherIssuer,
		"sub": "system:serviceaccount:pomerium:pomerium",
		"exp": now.Add(time.Hour).Unix(),
	})
	f.stub.setBearer(podToken)
	require.NoError(t, os.WriteFile(f.params.tokenFile, []byte(podToken), 0o600))

	resolver := f.build(t)

	// A token from the issuer the pod's token named dispatches and verifies...
	tok := f.stub.signJWT(t, map[string]any{
		"iss": otherIssuer,
		"sub": "system:serviceaccount:ns:sa",
		"aud": []string{"pomerium-agentic-as"},
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Unix(),
	})
	res, err := resolver.Verify(t.Context(), tok)
	require.NoError(t, err)
	assert.Equal(t, "cluster", res.ProviderName)

	// ...while one naming the API server's own URL does not match any provider,
	// even though the discovery document advertises exactly that issuer.
	_, err = resolver.Verify(t.Context(), f.token)
	require.ErrorIs(t, err, ErrNoMatchingIdentityProvider)
	assert.Zero(t, f.stub.discoveries.Load())
}

// TestNewIdentityProviderResolver_KubernetesPodTokenErrors: an unusable pod token
// costs this provider only. The build still succeeds — nothing reads the token
// there — and the failure surfaces on the tokens it would have verified, naming
// itself so a deny log says why nothing matched.
func TestNewIdentityProviderResolver_KubernetesPodTokenErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		content []byte // nil means "no file at all"
		wantErr string
	}{
		{"missing file", nil, "read kubernetes serviceaccount token"},
		{"not a JWT", []byte("an-opaque-legacy-token"), "read issuer from kubernetes serviceaccount token"},
		{"JWT without iss", []byte(encodeUnsignedJWT(t, map[string]any{"sub": "sa"})), "missing iss claim"},
		// A legacy non-projected token is a well-formed JWT, so only the
		// absolute-URL requirement rejects it. Registering it would have produced a
		// provider that rejects every token without saying why.
		{"legacy issuer", []byte(encodeUnsignedJWT(t, map[string]any{
			"iss": "kubernetes/serviceaccount",
			"sub": "system:serviceaccount:pomerium:pomerium",
		})), "projected (bound) token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newKubernetesClusterFixture(t)
			if tc.content == nil {
				require.NoError(t, os.Remove(f.params.tokenFile))
			} else {
				require.NoError(t, os.WriteFile(f.params.tokenFile, tc.content, 0o600))
			}

			resolver := f.build(t)

			_, err := resolver.Verify(t.Context(), f.token)
			require.ErrorIs(t, err, ErrNoMatchingIdentityProvider)
			assert.ErrorContains(t, err, "identity_providers[cluster]")
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestNewIdentityProviderResolver_KubernetesFailureIsolated is the regression this
// change is about: a kubernetes:/// provider that cannot resolve — no projected
// token, as on any non-Kubernetes host — used to fail the whole provider map,
// taking every unrelated provider with it.
func TestNewIdentityProviderResolver_KubernetesFailureIsolated(t *testing.T) {
	t.Parallel()

	f := newKubernetesClusterFixture(t)
	require.NoError(t, os.Remove(f.params.tokenFile))

	// An ordinary provider, sharing nothing with the broken one but the map.
	idp := mockidp.New(mockidp.Config{})
	issuer := idp.Start(t)
	providers := map[string]IdentityProvider{
		"cluster": f.providers["cluster"],
		"github": {
			Issuer:        issuer,
			Audiences:     []string{"pomerium"},
			SupportedAlgs: []string{"ES256"},
		},
	}
	resolver := newIdentityProviderResolver(t.Context(), providers, sharedJWKSClient{},
		withKubernetesInClusterParams(f.params))

	now := time.Now()
	res, err := resolver.Verify(t.Context(), idp.SignJWT(map[string]any{
		"iss": issuer,
		"sub": "repo:pomerium/pomerium",
		"aud": []string{"pomerium"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	}))
	require.NoError(t, err, "a broken kubernetes provider must not disable the others")
	assert.Equal(t, "github", res.ProviderName)

	// The broken one is still broken, and only for its own tokens.
	_, err = resolver.Verify(t.Context(), f.token)
	require.ErrorIs(t, err, ErrNoMatchingIdentityProvider)
}

func TestKubernetesIssuerFromToken(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	t.Run("reads iss, trimming the trailing newline", func(t *testing.T) {
		tok := encodeUnsignedJWT(t, map[string]any{"iss": "https://issuer.example", "sub": "sa"})
		issuer, err := kubernetesIssuerFromToken(writeTestFile(t, dir, "good", []byte(tok+"\n")))
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.example", issuer)
	})

	t.Run("rejects an issuer that is not a URL", func(t *testing.T) {
		tok := encodeUnsignedJWT(t, map[string]any{"iss": "kubernetes/serviceaccount"})
		_, err := kubernetesIssuerFromToken(writeTestFile(t, dir, "legacy", []byte(tok)))
		require.ErrorContains(t, err, "projected (bound) token")
	})
}

// TestDeferredKubernetesProvider_Recovers: a provider whose token was missing
// must start working once the token appears, without waiting for a configuration
// change — that recovery is the whole point of resolving on the dispatch path.
func TestDeferredKubernetesProvider_Recovers(t *testing.T) {
	t.Parallel()

	f := newKubernetesClusterFixture(t)
	podToken, err := os.ReadFile(f.params.tokenFile)
	require.NoError(t, err)
	require.NoError(t, os.Remove(f.params.tokenFile))

	clock := newTestClock()
	resolver := f.build(t, withIdentityProviderTimeNow(clock.now))

	_, err = resolver.Verify(t.Context(), f.token)
	require.ErrorIs(t, err, ErrNoMatchingIdentityProvider)

	require.NoError(t, os.WriteFile(f.params.tokenFile, podToken, 0o600))

	// Still inside the interval: the token is not re-read, so nothing changes.
	_, err = resolver.Verify(t.Context(), f.token)
	require.ErrorIs(t, err, ErrNoMatchingIdentityProvider)

	clock.advance(kubernetesResolveInterval)
	res, err := resolver.Verify(t.Context(), f.token)
	require.NoError(t, err)
	assert.Equal(t, "cluster", res.ProviderName)
}

// TestDeferredKubernetesProvider_IssuerRotation: an issuer migration reaches
// Pomerium as a token nothing matches, which is exactly the signal that makes the
// provider re-read the pod's token — so it self-corrects.
func TestDeferredKubernetesProvider_IssuerRotation(t *testing.T) {
	t.Parallel()

	f := newKubernetesClusterFixture(t)
	clock := newTestClock()
	resolver := f.build(t, withIdentityProviderTimeNow(clock.now))

	res, err := resolver.Verify(t.Context(), f.token)
	require.NoError(t, err)
	require.Equal(t, "cluster", res.ProviderName)

	// The cluster migrates: the kubelet rewrites the pod token, and workload tokens
	// now carry the new issuer.
	const migrated = "https://migrated.example"
	now := time.Now()
	newPodToken := f.stub.signJWT(t, map[string]any{
		"iss": migrated,
		"sub": "system:serviceaccount:pomerium:pomerium",
		"exp": now.Add(time.Hour).Unix(),
	})
	f.stub.setBearer(newPodToken)
	require.NoError(t, os.WriteFile(f.params.tokenFile, []byte(newPodToken+"\n"), 0o600))
	migratedTok := f.stub.signJWT(t, map[string]any{
		"iss": migrated,
		"sub": "system:serviceaccount:ns:sa",
		"aud": []string{"pomerium-agentic-as"},
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Unix(),
	})

	// Inside the interval the token is not re-read, so nothing has changed yet:
	// this is what keeps a flood of unmatched tokens from becoming a read per
	// request.
	_, err = resolver.Verify(t.Context(), migratedTok)
	require.ErrorIs(t, err, ErrNoMatchingIdentityProvider)
	res, err = resolver.Verify(t.Context(), f.token)
	require.NoError(t, err)
	require.Equal(t, "cluster", res.ProviderName)

	clock.advance(kubernetesResolveInterval)
	res, err = resolver.Verify(t.Context(), migratedTok)
	require.NoError(t, err)
	assert.Equal(t, "cluster", res.ProviderName)

	// And the old issuer is no longer accepted.
	clock.advance(kubernetesResolveInterval)
	_, err = resolver.Verify(t.Context(), f.token)
	assert.ErrorIs(t, err, ErrNoMatchingIdentityProvider)
}

// TestDeferredKubernetesProvider_TransientReadFailure: the kubelet replaces the
// token atomically, so a read that fails is transient. Dropping a working
// verifier over it would trade a recoverable gap for an outage.
func TestDeferredKubernetesProvider_TransientReadFailure(t *testing.T) {
	t.Parallel()

	f := newKubernetesClusterFixture(t)
	clock := newTestClock()
	resolver := f.build(t, withIdentityProviderTimeNow(clock.now))

	_, err := resolver.Verify(t.Context(), f.token)
	require.NoError(t, err)

	require.NoError(t, os.Remove(f.params.tokenFile))
	clock.advance(kubernetesResolveInterval)

	// The re-read fails, but a token from the last known issuer still verifies —
	// only the JWKS bearer, read per round-trip, is affected.
	rp, err := resolver.resolveUnverified(t.Context(), f.token)
	require.NoError(t, err)
	assert.Equal(t, "cluster", rp.Name)
}
