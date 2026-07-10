package licenseproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	enterprisepb "github.com/pomerium/pomerium/pkg/grpc/enterprise"
)

const (
	testAccount      = "account-id"
	testProduct      = "product-id"
	testInstallation = "installation-id"
	testHost         = "api.keygen.test"
	testSecretValue  = "license-key-canary"
	testMetadataKey  = "postgresManagedAccess"
)

func TestSealOpenAndVerify(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secret := []byte("01234567890123456789012345678901")
	response := signedResponse(t, privateKey, now, 42, testInstallation, testProduct, now.Add(time.Hour))

	evidence, err := Seal(secret, testInstallation, 42, response)
	require.NoError(t, err)
	lease, err := NewLease(testInstallation,
		[]enterprisepb.Capability{enterprisepb.Capability_CAPABILITY_POSTGRES_MANAGED_CREDENTIALS},
		now.Add(2*time.Minute), evidence)
	require.NoError(t, err)

	verified, err := VerifyLease(secret, lease, VerifyOptions{
		PublicKey: publicKey, AccountID: testAccount, ProductID: testProduct,
		InstallationID: testInstallation, Now: func() time.Time { return now },
		APIHost: testHost, APIScheme: "https",
		Validate: func(claims Claims) error {
			enabled, err := claims.MetadataBool(testMetadataKey)
			if err != nil || !enabled {
				return ErrInvalidClaims
			}
			return nil
		},
	})
	require.NoError(t, err)
	assert.Equal(t, now.Add(2*time.Minute), verified.ExpiresAt)
	assert.Equal(t, uint64(42), verified.Claims.ValidationNonce)
	assert.Equal(t, testInstallation, verified.Claims.InstallationID)

	encoded, err := proto.Marshal(lease)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), testSecretValue)
	assert.NotContains(t, lease.String(), testSecretValue)
	assert.NotContains(t, response.String(), testSecretValue)
	assert.NotContains(t, verified.Claims.String(), testSecretValue)
}

func TestEnvelopeBinding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secret := []byte("01234567890123456789012345678901")
	response := signedResponse(t, privateKey, now, 7, testInstallation, testProduct, now.Add(time.Hour))
	evidence, err := Seal(secret, testInstallation, 7, response)
	require.NoError(t, err)

	t.Run("wrong secret", func(t *testing.T) {
		_, err := Open([]byte("11234567890123456789012345678901"), testInstallation, evidence)
		assert.ErrorIs(t, err, ErrDecrypt)
	})
	t.Run("wrong installation", func(t *testing.T) {
		_, err := Open(secret, "another-installation", evidence)
		assert.ErrorIs(t, err, ErrDecrypt)
	})
	t.Run("nonce mutation", func(t *testing.T) {
		mutated := proto.Clone(evidence).(*enterprisepb.EncryptedKeygenEvidence)
		mutated.ValidationNonce++
		_, err := Open(secret, testInstallation, mutated)
		assert.ErrorIs(t, err, ErrDecrypt)
	})
	t.Run("ciphertext mutation", func(t *testing.T) {
		mutated := proto.Clone(evidence).(*enterprisepb.EncryptedKeygenEvidence)
		mutated.Ciphertext[0] ^= 1
		_, err := Open(secret, testInstallation, mutated)
		assert.ErrorIs(t, err, ErrDecrypt)
	})
	t.Run("unsupported version", func(t *testing.T) {
		mutated := proto.Clone(evidence).(*enterprisepb.EncryptedKeygenEvidence)
		mutated.Version++
		_, err := Open(secret, testInstallation, mutated)
		assert.ErrorIs(t, err, ErrInvalidEnvelope)
	})
}

func TestVerifyRejectsInvalidEvidence(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	baseOpts := VerifyOptions{
		PublicKey: publicKey, AccountID: testAccount, ProductID: testProduct,
		InstallationID: testInstallation, ValidationNonce: 99,
		Now: func() time.Time { return now }, APIHost: testHost, APIScheme: "https",
	}

	tests := []struct {
		name             string
		response         func(*Response)
		bodyNonce        uint64
		bodyInstallation string
		bodyProduct      string
		responseTime     time.Time
		want             error
	}{
		{name: "stale", responseTime: now.Add(-6 * time.Minute), want: ErrStaleResponse},
		{name: "future", responseTime: now.Add(time.Minute), want: ErrFutureResponse},
		{name: "wrong nonce", bodyNonce: 100, want: ErrInvalidClaims},
		{name: "wrong installation", bodyInstallation: "other", want: ErrInvalidClaims},
		{name: "wrong product", bodyProduct: "other", want: ErrInvalidClaims},
		{name: "wrong method", response: func(r *Response) { r.method = "GET" }, want: ErrInvalidResponse},
		{name: "wrong host", response: func(r *Response) { r.url = strings.Replace(r.url, testHost, "evil.test", 1) }, want: ErrInvalidResponse},
		{name: "wrong account", response: func(r *Response) { r.url = strings.Replace(r.url, testAccount, "other", 1) }, want: ErrInvalidResponse},
		{name: "digest mutation", response: func(r *Response) { r.digest = "sha-256=bad" }, want: ErrInvalidSignature},
		{name: "body mutation", response: func(r *Response) { r.body[0] ^= 1 }, want: ErrInvalidSignature},
		{name: "signature mutation", response: func(r *Response) { r.signature = `signature="bad"` }, want: ErrInvalidSignature},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			responseTime := tc.responseTime
			if responseTime.IsZero() {
				responseTime = now
			}
			nonce := tc.bodyNonce
			if nonce == 0 {
				nonce = 99
			}
			installation := tc.bodyInstallation
			if installation == "" {
				installation = testInstallation
			}
			product := tc.bodyProduct
			if product == "" {
				product = testProduct
			}
			response := signedResponse(t, privateKey, responseTime, nonce, installation, product, now.Add(time.Hour))
			if tc.response != nil {
				tc.response(response)
			}
			_, err := Verify(response, baseOpts)
			assert.ErrorIs(t, err, tc.want)
			assert.NotContains(t, fmt.Sprint(err), testSecretValue)
		})
	}
}

func TestVerifyExpiryAndValidator(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	response := signedResponse(t, privateKey, now, 5, testInstallation, testProduct, now.Add(time.Minute))
	opts := VerifyOptions{
		PublicKey: publicKey, AccountID: testAccount, ProductID: testProduct,
		InstallationID: testInstallation, ValidationNonce: 5,
		Now: func() time.Time { return now }, APIHost: testHost, APIScheme: "https",
	}
	verified, err := Verify(response, opts)
	require.NoError(t, err)
	assert.Equal(t, now.Add(time.Minute), verified.ExpiresAt)

	opts.Validate = func(Claims) error { return errors.New(testSecretValue) }
	_, err = Verify(response, opts)
	assert.ErrorIs(t, err, ErrInvalidClaims)
	assert.NotContains(t, fmt.Sprint(err), testSecretValue)
}

func TestPublicKey(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	decoded, err := PublicKey(fmt.Sprintf("%x", publicKey))
	require.NoError(t, err)
	assert.Equal(t, publicKey, decoded)

	_, err = PublicKey("not-a-key")
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestPinnedKeygenValues(t *testing.T) {
	assert.NotEmpty(t, KeygenAccountID)
	assert.NotEmpty(t, KeygenProductID)
	assert.NotEmpty(t, ManagedPostgresMetadataKey)
	assert.NotEmpty(t, ManagedPostgresEntitlement)
	_, err := PublicKey(KeygenResponseSigningPublicKey)
	require.NoError(t, err)
}

func signedResponse(t *testing.T, privateKey ed25519.PrivateKey, responseTime time.Time, nonce uint64, installationID, productID string, expiry time.Time) *Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"meta": map[string]any{
			"valid": true,
			"code":  "VALID",
			"nonce": nonce,
			"scope": map[string]any{
				"fingerprint":  installationID,
				"product":      productID,
				"entitlements": []string{"postgres-managed-credentials"},
			},
		},
		"data": map[string]any{
			"attributes": map[string]any{
				"key":      testSecretValue,
				"expiry":   expiry.Format(time.RFC3339),
				"metadata": map[string]any{testMetadataKey: true},
			},
		},
	})
	require.NoError(t, err)
	rawURL := fmt.Sprintf("https://%s/v1/accounts/%s/licenses/license-id/actions/validate", testHost, url.PathEscape(testAccount))
	digestBytes := sha256.Sum256(body)
	digest := "sha-256=" + base64.StdEncoding.EncodeToString(digestBytes[:])
	date := responseTime.Format(time.RFC1123)
	message := fmt.Sprintf("(request-target): post %s\nhost: %s\ndate: %s\ndigest: %s",
		"/v1/accounts/"+url.PathEscape(testAccount)+"/licenses/license-id/actions/validate", testHost, date, digest)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(message)))
	return NewResponse("POST", rawURL, body, date, digest,
		fmt.Sprintf(`keyid="key",algorithm="ed25519",signature="%s"`, signature))
}
