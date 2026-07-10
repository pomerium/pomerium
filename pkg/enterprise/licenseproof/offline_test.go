package licenseproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	enterprisepb "github.com/pomerium/pomerium/pkg/grpc/enterprise"
)

const offlineKeyCanary = "offline-signed-key-canary"

func TestVerifyOfflineSignedKey(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signedKey := signedOfflineKey(t, privateKey, offlinePayload{
		ProductID: testProduct, CreatedAt: now.Add(-time.Hour), ExpiresAt: ptr(now.Add(time.Hour)),
		AllowOffline: true, PostgresManaged: true, Canary: offlineKeyCanary,
	})

	claims, err := VerifyOfflineSignedKey(signedKey, OfflineVerifyOptions{
		PublicKey: publicKey, ProductID: testProduct, Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	assert.Equal(t, testProduct, claims.ProductID)
	assert.Equal(t, now.Add(time.Hour), claims.LicenseExpiresAt)
	assert.NotContains(t, claims.String(), offlineKeyCanary)
}

func TestVerifyOfflineSignedKeyRejectsMalformedWithoutPanic(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	inputs := []string{
		"", ".", "key/", "key/a", "key/a.", "key/.a", "key/a.b.c", "other/a.b",
		"key/a/b.c", "key/not+url.c2ln", " key/e30=.c2ln", "key/e30=.c2ln\n",
		strings.Repeat("a", maxOfflineSignedKeySize+1),
	}
	for i, input := range inputs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			assert.NotPanics(t, func() {
				_, err := VerifyOfflineSignedKey(input, OfflineVerifyOptions{
					PublicKey: publicKey, ProductID: testProduct,
				})
				assert.ErrorIs(t, err, ErrInvalidOfflineKey)
			})
		})
	}
}

func TestVerifyOfflineSignedKeyRejectsInvalidClaims(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	base := offlinePayload{
		ProductID: testProduct, CreatedAt: now.Add(-time.Hour), ExpiresAt: ptr(now.Add(time.Hour)),
		AllowOffline: true, PostgresManaged: true,
	}
	testCases := []struct {
		name   string
		mutate func(*offlinePayload)
	}{
		{name: "product", mutate: func(p *offlinePayload) { p.ProductID = "wrong-product" }},
		{name: "created missing", mutate: func(p *offlinePayload) { p.CreatedAt = time.Time{} }},
		{name: "created future", mutate: func(p *offlinePayload) { p.CreatedAt = now.Add(time.Minute) }},
		{name: "expiry missing", mutate: func(p *offlinePayload) { p.ExpiresAt = nil }},
		{name: "expiry before created", mutate: func(p *offlinePayload) { p.ExpiresAt = ptr(now.Add(-2 * time.Hour)) }},
		{name: "expired", mutate: func(p *offlinePayload) { p.ExpiresAt = ptr(now.Add(-time.Minute)) }},
		{name: "offline disabled", mutate: func(p *offlinePayload) { p.AllowOffline = false }},
		{name: "postgres disabled", mutate: func(p *offlinePayload) { p.PostgresManaged = false }},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := base
			tc.mutate(&payload)
			signedKey := signedOfflineKey(t, privateKey, payload)
			_, err := VerifyOfflineSignedKey(signedKey, OfflineVerifyOptions{
				PublicKey: publicKey, ProductID: testProduct, Now: func() time.Time { return now },
			})
			assert.ErrorIs(t, err, ErrInvalidClaims)
			assert.NotContains(t, fmt.Sprint(err), offlineKeyCanary)
		})
	}
}

func TestVerifyOfflineSignedKeyRejectsInvalidSignature(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signedKey := signedOfflineKey(t, privateKey, offlinePayload{
		ProductID: testProduct, CreatedAt: now.Add(-time.Hour), ExpiresAt: ptr(now.Add(time.Hour)),
		AllowOffline: true, PostgresManaged: true,
	})
	parts := strings.Split(signedKey, ".")
	signature, err := base64.URLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	signature[0] ^= 1
	mutated := parts[0] + "." + base64.URLEncoding.EncodeToString(signature)

	_, err = VerifyOfflineSignedKey(mutated, OfflineVerifyOptions{
		PublicKey: publicKey, ProductID: testProduct, Now: func() time.Time { return now },
	})
	assert.ErrorIs(t, err, ErrInvalidOfflineKey)
}

func TestOfflineLeaseRoundTripAndBinding(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secret := []byte("01234567890123456789012345678901")
	signedKey := signedOfflineKey(t, privateKey, offlinePayload{
		ProductID: testProduct, CreatedAt: now.Add(-time.Hour), ExpiresAt: ptr(now.Add(time.Hour)),
		AllowOffline: true, PostgresManaged: true, Canary: offlineKeyCanary,
	})
	evidence, err := SealOfflineKey(secret, testInstallation, now, signedKey)
	require.NoError(t, err)
	lease, err := NewOfflineLease(testInstallation,
		[]enterprisepb.Capability{enterprisepb.Capability_CAPABILITY_POSTGRES_MANAGED_CREDENTIALS},
		now.Add(2*time.Minute), evidence)
	require.NoError(t, err)

	verified, err := VerifyOfflineLease(secret, lease, testInstallation, OfflineVerifyOptions{
		PublicKey: publicKey, ProductID: testProduct, Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	assert.Equal(t, now.Add(2*time.Minute), verified.ExpiresAt, "declared expiry may only shorten evidence")
	encoded, err := proto.Marshal(lease)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), signedKey)
	assert.NotContains(t, string(encoded), offlineKeyCanary)
	assert.NotContains(t, lease.String(), offlineKeyCanary)

	replayed := proto.Clone(lease).(*enterprisepb.CapabilityLease)
	replayed.InstallationId = "another-installation"
	_, err = VerifyOfflineLease(secret, replayed, "another-installation", OfflineVerifyOptions{
		PublicKey: publicKey, ProductID: testProduct, Now: func() time.Time { return now },
	})
	assert.ErrorIs(t, err, ErrDecrypt)
	assert.NotContains(t, fmt.Sprint(err), offlineKeyCanary)

	wrongVersion := proto.Clone(lease).(*enterprisepb.CapabilityLease)
	wrongVersion.OfflineKeyEvidence.Version++
	_, err = VerifyOfflineLease(secret, wrongVersion, testInstallation, OfflineVerifyOptions{
		PublicKey: publicKey, ProductID: testProduct, Now: func() time.Time { return now },
	})
	assert.ErrorIs(t, err, ErrInvalidEnvelope)

	mutatedCiphertext := proto.Clone(lease).(*enterprisepb.CapabilityLease)
	mutatedCiphertext.OfflineKeyEvidence.Ciphertext[0] ^= 1
	_, err = VerifyOfflineLease(secret, mutatedCiphertext, testInstallation, OfflineVerifyOptions{
		PublicKey: publicKey, ProductID: testProduct, Now: func() time.Time { return now },
	})
	assert.ErrorIs(t, err, ErrDecrypt)
}

func TestOfflineLeaseRejectsStaleAndAmbiguousEvidence(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secret := []byte("01234567890123456789012345678901")
	signedKey := signedOfflineKey(t, privateKey, offlinePayload{
		ProductID: testProduct, CreatedAt: now.Add(-time.Hour), ExpiresAt: ptr(now.Add(time.Hour)),
		AllowOffline: true, PostgresManaged: true,
	})
	evidence, err := SealOfflineKey(secret, testInstallation, now.Add(-6*time.Minute), signedKey)
	require.NoError(t, err)
	lease, err := NewOfflineLease(testInstallation, nil, now.Add(time.Minute), evidence)
	require.NoError(t, err)
	opts := OfflineVerifyOptions{PublicKey: publicKey, ProductID: testProduct, Now: func() time.Time { return now }}

	_, err = VerifyOfflineLease(secret, lease, testInstallation, opts)
	assert.ErrorIs(t, err, ErrStaleResponse)

	ambiguous := proto.Clone(lease).(*enterprisepb.CapabilityLease)
	ambiguous.KeygenEvidence = &enterprisepb.EncryptedKeygenEvidence{Version: EvidenceVersion}
	_, err = VerifyOfflineLease(secret, ambiguous, testInstallation, opts)
	assert.ErrorIs(t, err, ErrInvalidEnvelope)
}

type offlinePayload struct {
	ProductID       string
	CreatedAt       time.Time
	ExpiresAt       *time.Time
	AllowOffline    bool
	PostgresManaged bool
	Canary          string
}

func signedOfflineKey(t *testing.T, privateKey ed25519.PrivateKey, p offlinePayload) string {
	t.Helper()
	dataset, err := json.Marshal(map[string]any{
		"product": map[string]any{"id": p.ProductID},
		"license": map[string]any{
			"created": p.CreatedAt,
			"expires": p.ExpiresAt,
			"metadata": map[string]any{
				"allowOfflineVerification": p.AllowOffline,
				"postgresManagedAccess":    p.PostgresManaged,
				"canary":                   p.Canary,
			},
		},
	})
	require.NoError(t, err)
	encodedDataset := base64.URLEncoding.EncodeToString(dataset)
	signingData := "key/" + encodedDataset
	signature := ed25519.Sign(privateKey, []byte(signingData))
	return signingData + "." + base64.URLEncoding.EncodeToString(signature)
}

func ptr[T any](value T) *T { return &value }
