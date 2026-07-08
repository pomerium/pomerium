package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIdentityProviderResolver_BadCA_ShouldSurfaceError is the regression test
// for the silent-degradation finding: when certificate_authority is explicitly
// set (the documented private-CA / Kubernetes cluster-CA case) but fails to
// load, the old code only logged and fell back to system roots, so the
// resolver was built against the wrong trust set. There was no config-time
// error; the operator saw every JWT-bearer token silently rejected at runtime
// (JWKS fetch failing with "certificate signed by unknown authority").
//
// The fix makes an explicitly-configured but unloadable CA a hard error
// surfaced from IdentityProviderResolver(); this test asserts that.
func TestIdentityProviderResolver_BadCA_ShouldSurfaceError(t *testing.T) {
	t.Parallel()

	providers := map[string]IdentityProvider{
		"k8s": {Issuer: "https://issuer.example.com", Audiences: []string{"aud"}, SupportedAlgs: []string{"ES256"}},
	}
	// CA is explicitly configured but malformed (not valid base64-encoded PEM),
	// so cryptutil.GetCertPool returns an error.
	cfg := New(&Options{CA: "@@@not-valid-base64-or-pem@@@", IdentityProviders: providers})

	_, err := cfg.IdentityProviderResolver()
	require.Error(t, err,
		"an explicitly-configured certificate_authority that fails to load must be a hard error, "+
			"not a silent fallback to system roots")
}

// TestIdentityProvider_Validate_RejectsNonAbsoluteIssuer is the regression test
// for the near-no-op issuer validation: the old Validate only did
// url.Parse(Issuer), which accepts bare strings like "foo" (no scheme, not
// absolute), so a bogus issuer passed validation and only failed later at OIDC
// discovery/verification time. The fix requires the issuer to be an absolute
// URL; this test asserts "foo" is rejected at config validation.
func TestIdentityProvider_Validate_RejectsNonAbsoluteIssuer(t *testing.T) {
	t.Parallel()

	ip := IdentityProvider{Issuer: "foo", Audiences: []string{"aud"}}
	require.Error(t, ip.Validate(),
		`issuer "foo" is not an absolute http(s) URL and should be rejected at config validation`)
}

// TestIdentityProvider_Validate_RejectsPlaintextHTTPKeySource is the regression
// test for the "signing keys over unauthenticated HTTP" finding. The old
// Validate accepted a jwks_url with an http:// scheme and put no scheme
// constraint on the issuer, so signing-key material could be fetched over
// plaintext HTTP — letting an on-path attacker substitute the JWKS and forge
// tokens that then verify (a signature bypass rooted in key retrieval).
//
// The fix requires https for both jwks_url and the (discovery) issuer, with an
// exception for loopback hosts (local dev / tests). This test asserts the
// non-loopback http cases are rejected.
func TestIdentityProvider_Validate_RejectsPlaintextHTTPKeySource(t *testing.T) {
	t.Parallel()

	t.Run("http jwks_url", func(t *testing.T) {
		ip := IdentityProvider{
			Issuer:    "https://issuer.example.com",
			JWKSURL:   "http://issuer.example.com/jwks",
			Audiences: []string{"aud"},
		}
		require.Error(t, ip.Validate(),
			"a plaintext-http jwks_url exposes signing keys to on-path substitution")
	})

	t.Run("http issuer used for discovery", func(t *testing.T) {
		ip := IdentityProvider{
			Issuer:    "http://issuer.example.com",
			Audiences: []string{"aud"},
		}
		require.Error(t, ip.Validate(),
			"an http issuer means the discovery document and JWKS are fetched over plaintext")
	})
}
