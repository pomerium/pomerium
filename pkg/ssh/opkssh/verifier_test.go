package opkssh

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestVerify_SentinelErrorContract verifies that verification failures (wrong
// audience, wrong issuer) do NOT satisfy errors.Is(ErrNotOPKSSHKey) or
// errors.Is(ErrInvalidPKToken). If they did, the auth handler would silently
// fall through to keyboard-interactive instead of rejecting the cert.
func TestVerify_SentinelErrorContract(t *testing.T) {
	idp := startTestOIDC(t)
	otherIDP := startTestOIDC(t)

	cases := []struct {
		name   string
		issuer string
		aud    string
		token  string
	}{
		{
			name:   "wrong audience must not alias ErrNotOPKSSHKey",
			issuer: idp.url,
			aud:    "correct-client",
			token:  buildCompactToken(t, idp, "wrong-client", "sub", "e@x.co"),
		},
		{
			name:   "wrong issuer must not alias ErrNotOPKSSHKey",
			issuer: otherIDP.url,
			aud:    "client",
			token:  buildCompactToken(t, idp, "client", "sub", "e@x.co"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewVerifier(tc.issuer, []string{tc.aud})
			require.NoError(t, err)

			cert := buildTestCert(t, map[string]string{
				opkSSHCertExtension: tc.token,
			})
			_, err = v.Verify(context.Background(), cert)
			require.Error(t, err)
			assert.False(t, errors.Is(err, ErrNotOPKSSHKey),
				"verification failure must not satisfy ErrNotOPKSSHKey: %v", err)
			assert.False(t, errors.Is(err, ErrInvalidPKToken),
				"verification failure must not satisfy ErrInvalidPKToken: %v", err)
		})
	}
}

// TestVerify_SentinelErrorPositive verifies that the correct sentinel errors
// are returned for keys that should produce them.
func TestVerify_SentinelErrorPositive(t *testing.T) {
	t.Run("plain key returns ErrNotOPKSSHKey", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		sshPub, err := ssh.NewPublicKey(pub)
		require.NoError(t, err)

		v, err := NewVerifier("https://example.test", []string{"c"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), sshPub)
		assert.True(t, errors.Is(err, ErrNotOPKSSHKey), "plain key: want ErrNotOPKSSHKey, got %v", err)
	})

	t.Run("cert without extension returns ErrNotOPKSSHKey", func(t *testing.T) {
		cert := buildTestCert(t, nil)
		v, err := NewVerifier("https://example.test", []string{"c"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		assert.True(t, errors.Is(err, ErrNotOPKSSHKey), "no-ext cert: want ErrNotOPKSSHKey, got %v", err)
	})

	t.Run("host cert with extension returns ErrNotOPKSSHKey", func(t *testing.T) {
		idp := startTestOIDC(t)
		compact := buildCompactToken(t, idp, "client", "sub", "e@x.co")
		cert := buildTestCert(t, map[string]string{opkSSHCertExtension: compact}, withCertType(ssh.HostCert))
		v, err := NewVerifier(idp.url, []string{"client"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		assert.True(t, errors.Is(err, ErrNotOPKSSHKey), "host cert: want ErrNotOPKSSHKey, got %v", err)
	})

	t.Run("malformed compact returns ErrInvalidPKToken", func(t *testing.T) {
		cert := buildTestCert(t, map[string]string{opkSSHCertExtension: "only-one-segment"})
		v, err := NewVerifier("https://example.test", []string{"c"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		assert.True(t, errors.Is(err, ErrInvalidPKToken), "malformed: want ErrInvalidPKToken, got %v", err)
	})

	t.Run("future valid-after returns plain error", func(t *testing.T) {
		idp := startTestOIDC(t)
		cert := buildTestCert(t, map[string]string{
			opkSSHCertExtension: buildCompactToken(t, idp, "client", "sub", "e@x.co"),
		}, withValidAfter(time.Now().Add(time.Hour)))
		v, err := NewVerifier(idp.url, []string{"client"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not yet valid")
		assert.False(t, errors.Is(err, ErrNotOPKSSHKey))
		assert.False(t, errors.Is(err, ErrInvalidPKToken))
	})

	t.Run("expired valid-before returns plain error", func(t *testing.T) {
		idp := startTestOIDC(t)
		cert := buildTestCert(t, map[string]string{
			opkSSHCertExtension: buildCompactToken(t, idp, "client", "sub", "e@x.co"),
		}, withValidBefore(time.Now().Add(-time.Hour)))
		v, err := NewVerifier(idp.url, []string{"client"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
		assert.False(t, errors.Is(err, ErrNotOPKSSHKey))
		assert.False(t, errors.Is(err, ErrInvalidPKToken))
	})
}

func TestVerify_CICFailures(t *testing.T) {
	idp := startTestOIDC(t)

	t.Run("missing CIC segments", func(t *testing.T) {
		idToken := mintTestToken(t, idp, "client", "sub", "e@x.co", "")
		cert := buildTestCert(t, map[string]string{
			opkSSHCertExtension: reorderJWSToCompact(t, idToken),
		})
		v, err := NewVerifier(idp.url, []string{"client"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrCICBindingFailed), "missing CIC: want ErrCICBindingFailed, got %v", err)
	})

	t.Run("wrong nonce", func(t *testing.T) {
		compact, _ := buildCompactTokenWithNonce(t, idp, "client", "sub", "e@x.co", "wrong-nonce")
		cert := buildTestCert(t, map[string]string{opkSSHCertExtension: compact})
		v, err := NewVerifier(idp.url, []string{"client"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrCICBindingFailed), "wrong nonce: want ErrCICBindingFailed, got %v", err)
		assert.False(t, errors.Is(err, ErrNotOPKSSHKey))
	})

	t.Run("wrong CIC signature", func(t *testing.T) {
		compact := buildCompactToken(t, idp, "client", "sub", "e@x.co")
		cert := buildTestCert(t, map[string]string{
			opkSSHCertExtension: mutateCompactSegment(t, compact, 4),
		})
		v, err := NewVerifier(idp.url, []string{"client"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrCICBindingFailed), "wrong signature: want ErrCICBindingFailed, got %v", err)
	})

	t.Run("wrong bound key", func(t *testing.T) {
		compact, sshPub := buildCompactTokenForKey(t, idp, "client", "sub", "e@x.co")
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		otherSSHPub, err := ssh.NewPublicKey(otherPub)
		require.NoError(t, err)
		cert := buildTestCert(t, map[string]string{
			opkSSHCertExtension: compact,
		}, withPublicKey(otherSSHPub))
		require.NotEqual(t, sshPub.Marshal(), otherSSHPub.Marshal())
		v, err := NewVerifier(idp.url, []string{"client"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrCICBindingFailed), "wrong key: want ErrCICBindingFailed, got %v", err)
	})

	t.Run("malformed CIC header", func(t *testing.T) {
		compact := buildCompactToken(t, idp, "client", "sub", "e@x.co")
		cert := buildTestCert(t, map[string]string{
			opkSSHCertExtension: replaceCompactSegment(t, compact, 3, "%"),
		})
		v, err := NewVerifier(idp.url, []string{"client"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrCICBindingFailed), "malformed CIC header: want ErrCICBindingFailed, got %v", err)
	})

	t.Run("unsupported CIC algorithm", func(t *testing.T) {
		compact, _ := buildCompactTokenWithHeaderAlg(t, idp, "client", "sub", "e@x.co", "RS256")
		cert := buildTestCert(t, map[string]string{opkSSHCertExtension: compact})
		v, err := NewVerifier(idp.url, []string{"client"})
		require.NoError(t, err)
		_, err = v.Verify(context.Background(), cert)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrCICBindingFailed), "unsupported alg: want ErrCICBindingFailed, got %v", err)
	})
}

func TestVerify_UpstreamFixtureWireCompat(t *testing.T) {
	// Generated from upstream openpubkey v0.23.0 using
	// clientinstance.NewClaims + Claims.Sign + pktoken.Compact.
	fixture := readUpstreamFixture(t)
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fixture.SSHPublicKeyAuthorized)) //nolint:dogsled
	require.NoError(t, err)

	opJWS, err := extractOPJWSFromCompact(fixture.Compact)
	require.NoError(t, err)
	assert.Len(t, strings.Split(opJWS, "."), 3)

	err = verifyCICBinding(fixture.Compact, fixture.Nonce, sshPub)
	require.NoError(t, err)
}

type testOIDC struct {
	url    string
	signer jose.Signer
}

func startTestOIDC(t *testing.T) *testOIDC {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
	thumb, _ := jwk.Thumbprint(crypto.SHA256)
	jwk.KeyID = hex.EncodeToString(thumb)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID),
	)
	require.NoError(t, err)
	to := &testOIDC{signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                to.url,
			"jwks_uri":                              to.url + "/.well-known/jwks.json",
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"authorization_endpoint":                to.url + "/auth",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	srv := httptest.NewServer(mux)
	to.url = srv.URL
	t.Cleanup(srv.Close)
	return to
}

func mintTestToken(t *testing.T, idp *testOIDC, aud, sub, email, nonce string) string {
	t.Helper()
	claims := struct {
		Iss   string           `json:"iss"`
		Aud   string           `json:"aud"`
		Sub   string           `json:"sub"`
		Email string           `json:"email"`
		Nonce string           `json:"nonce,omitempty"`
		Exp   *jwt.NumericDate `json:"exp"`
		Iat   *jwt.NumericDate `json:"iat"`
	}{idp.url, aud, sub, email, nonce, jwt.NewNumericDate(time.Now().Add(time.Hour)), jwt.NewNumericDate(time.Now())}
	tok, err := jwt.Signed(idp.signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return tok
}

type certOptions struct {
	key         ssh.PublicKey
	certType    uint32
	validAfter  uint64
	validBefore uint64
}

func withCertType(certType uint32) func(*certOptions) {
	return func(opts *certOptions) { opts.certType = certType }
}

func withPublicKey(key ssh.PublicKey) func(*certOptions) {
	return func(opts *certOptions) { opts.key = key }
}

func withValidAfter(ts time.Time) func(*certOptions) {
	return func(opts *certOptions) { opts.validAfter = uint64(ts.Unix()) }
}

func withValidBefore(ts time.Time) func(*certOptions) {
	return func(opts *certOptions) { opts.validBefore = uint64(ts.Unix()) }
}

func buildTestCert(t *testing.T, extensions map[string]string, opts ...func(*certOptions)) *ssh.Certificate {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	options := certOptions{
		key:         sshPub,
		certType:    ssh.UserCert,
		validAfter:  uint64(time.Now().Add(-time.Minute).Unix()),
		validBefore: uint64(time.Now().Add(time.Hour).Unix()),
	}
	for _, opt := range opts {
		opt(&options)
	}

	cert := &ssh.Certificate{
		Key:         options.key,
		CertType:    options.certType,
		ValidAfter:  options.validAfter,
		ValidBefore: options.validBefore,
		Permissions: ssh.Permissions{Extensions: extensions},
	}
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	require.NoError(t, err)
	require.NoError(t, cert.SignCert(rand.Reader, caSigner))
	return cert
}

func reorderJWSToCompact(t *testing.T, jws string) string {
	t.Helper()
	parts := strings.Split(jws, ".")
	require.Len(t, parts, 3)
	return parts[1] + ":" + parts[0] + ":" + parts[2]
}

func buildCompactToken(t *testing.T, idp *testOIDC, aud, sub, email string) string {
	t.Helper()
	compact, _ := buildCompactTokenWithNonce(t, idp, aud, sub, email, "")
	return compact
}

func buildCompactTokenForKey(t *testing.T, idp *testOIDC, aud, sub, email string) (string, ssh.PublicKey) {
	t.Helper()
	compact, sshPub, _ := buildCompactTokenWithCustomKey(t, idp, aud, sub, email, "", "EdDSA")
	return compact, sshPub
}

func buildCompactTokenWithHeaderAlg(t *testing.T, idp *testOIDC, aud, sub, email, alg string) (string, ssh.PublicKey) {
	t.Helper()
	compact, sshPub, _ := buildCompactTokenWithCustomKey(t, idp, aud, sub, email, "", alg)
	return compact, sshPub
}

func buildCompactTokenWithNonce(t *testing.T, idp *testOIDC, aud, sub, email, nonceOverride string) (string, ssh.PublicKey) {
	t.Helper()
	compact, sshPub, _ := buildCompactTokenWithCustomKey(t, idp, aud, sub, email, nonceOverride, "EdDSA")
	return compact, sshPub
}

func buildCompactTokenWithCustomKey(t *testing.T, idp *testOIDC, aud, sub, email, nonceOverride, alg string) (string, ssh.PublicKey, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	protectedSegment, nonce := buildCICProtectedSegment(t, pub, alg)
	if nonceOverride != "" {
		nonce = nonceOverride
	}
	idToken := mintTestToken(t, idp, aud, sub, email, nonce)
	return buildCompactWithCIC(t, idToken, protectedSegment, priv), sshPub, nonce
}

func buildCICProtectedSegment(t *testing.T, pub ed25519.PublicKey, alg string) (string, string) {
	t.Helper()

	jwk := jose.JSONWebKey{Key: pub, Algorithm: alg, Use: "sig"}
	upkJSON, err := json.Marshal(jwk)
	require.NoError(t, err)

	headerJSON, err := json.Marshal(struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		Upk json.RawMessage `json:"upk"`
		Rz  string          `json:"rz"`
	}{
		Typ: "CIC",
		Alg: alg,
		Upk: upkJSON,
		Rz:  strings.Repeat("a", 64),
	})
	require.NoError(t, err)

	sum := sha3.Sum256(headerJSON)
	return base64.RawURLEncoding.EncodeToString(headerJSON), base64.RawURLEncoding.EncodeToString(sum[:])
}

func buildCompactWithCIC(t *testing.T, idToken, protectedSegment string, priv ed25519.PrivateKey) string {
	t.Helper()

	parts := strings.Split(idToken, ".")
	require.Len(t, parts, 3)
	signingInput := protectedSegment + "." + parts[1]
	cicSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(signingInput)))
	return parts[1] + ":" + parts[0] + ":" + parts[2] + ":" + protectedSegment + ":" + cicSig
}

func mutateCompactSegment(t *testing.T, compact string, idx int) string {
	t.Helper()
	parts := strings.Split(compact, ":")
	require.Greater(t, len(parts), idx)
	require.NotEmpty(t, parts[idx])
	last := parts[idx][len(parts[idx])-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	parts[idx] = parts[idx][:len(parts[idx])-1] + string(repl)
	return strings.Join(parts, ":")
}

func replaceCompactSegment(t *testing.T, compact string, idx int, replacement string) string {
	t.Helper()
	parts := strings.Split(compact, ":")
	require.Greater(t, len(parts), idx)
	parts[idx] = replacement
	return strings.Join(parts, ":")
}

type upstreamFixture struct {
	Compact                string `json:"compact"`
	Nonce                  string `json:"nonce"`
	SSHPublicKeyAuthorized string `json:"ssh_public_key_authorized"`
}

func readUpstreamFixture(t *testing.T) upstreamFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "upstream_cic_fixture.json"))
	require.NoError(t, err)
	var fixture upstreamFixture
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.NotEmpty(t, fixture.Compact)
	require.NotEmpty(t, fixture.Nonce)
	require.NotEmpty(t, fixture.SSHPublicKeyAuthorized)
	return fixture
}
