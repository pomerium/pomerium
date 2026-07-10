package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/enterprise/licenseproof"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	enterprisepb "github.com/pomerium/pomerium/pkg/grpc/enterprise"
)

const (
	testAccount            = "account-id"
	testProduct            = "product-id"
	testInstallation       = "installation-id"
	testHost               = "api.keygen.test"
	testLicenseCanary      = "license-key-canary"
	testConfigSecretCanary = "config-secret-canary-12345678901"
	testWrongSecretCanary  = "wrong-config-secret-canary-12345"
	testTransportCanary    = "databroker-transport-canary"
	testEvidenceCanary     = "encrypted-evidence-canary"
)

func TestConsumerVerifyManagedPostgres(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secret := []byte(testConfigSecretCanary)
	lease := newSignedLease(t, privateKey, secret, now, true,
		[]string{licenseproof.ManagedPostgresEntitlement}, now.Add(time.Hour), now.Add(2*time.Minute))
	record := leaseRecord(t, lease)
	// DataBroker TTL/record age is cleanup metadata, not entitlement authority.
	record.ModifiedAt = timestamppb.New(now.Add(-24 * time.Hour))

	client := mock_databroker.NewMockDataBrokerServiceClient(gomock.NewController(t))
	client.EXPECT().Get(gomock.Any(), gomock.Eq(&databroker.GetRequest{
		Type: licenseproof.RecordTypeURL,
		Id:   licenseproof.RecordID,
	})).Return(&databroker.GetResponse{Record: record}, nil)
	consumer := testConsumer(publicKey, now, client)

	expiresAt, err := consumer.VerifyManagedPostgres(t.Context(), testAuthority(t, secret))
	require.NoError(t, err)
	assert.Equal(t, now.Add(2*time.Minute), expiresAt)
}

func TestConsumerUnsignedLeaseExpiryCannotExtendOnlineAuthority(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secret := []byte(testConfigSecretCanary)
	lease := newSignedLease(t, privateKey, secret, now, true,
		[]string{licenseproof.ManagedPostgresEntitlement}, now.Add(time.Minute), now.Add(24*time.Hour))

	client := mock_databroker.NewMockDataBrokerServiceClient(gomock.NewController(t))
	client.EXPECT().Get(gomock.Any(), gomock.Any()).Return(
		&databroker.GetResponse{Record: leaseRecord(t, lease)}, nil)
	consumer := testConsumer(publicKey, now, client)

	expiresAt, err := consumer.VerifyManagedPostgres(t.Context(), testAuthority(t, secret))
	require.NoError(t, err)
	assert.Equal(t, now.Add(time.Minute), expiresAt, "unsigned lease expiry must not outlive signed claims")
}

func TestConsumerVerifyManagedPostgresOffline(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secret := []byte(testConfigSecretCanary)
	signedKey := signedOfflineKey(t, privateKey, now)
	evidence, err := licenseproof.SealOfflineKey(secret, testInstallation, now, signedKey)
	require.NoError(t, err)
	lease, err := licenseproof.NewOfflineLease(testInstallation,
		[]enterprisepb.Capability{enterprisepb.Capability_CAPABILITY_POSTGRES_MANAGED_CREDENTIALS},
		now.Add(2*time.Minute), evidence)
	require.NoError(t, err)

	client := mock_databroker.NewMockDataBrokerServiceClient(gomock.NewController(t))
	client.EXPECT().Get(gomock.Any(), gomock.Eq(&databroker.GetRequest{
		Type: licenseproof.RecordTypeURL,
		Id:   licenseproof.RecordID,
	})).Return(&databroker.GetResponse{Record: leaseRecord(t, lease)}, nil)
	consumer := testConsumer(publicKey, now, client)

	expiresAt, err := consumer.VerifyManagedPostgres(t.Context(), testAuthority(t, secret))
	require.NoError(t, err)
	assert.Equal(t, now.Add(2*time.Minute), expiresAt)
}

func TestConsumerDeniesWithoutLeakingSensitiveInputs(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secret := []byte(testConfigSecretCanary)

	validLease := newSignedLease(t, privateKey, secret, now, true, nil,
		now.Add(time.Hour), now.Add(2*time.Minute))
	missingMetadataLease := newSignedLease(t, privateKey, secret, now, false, nil,
		now.Add(time.Hour), now.Add(2*time.Minute))
	wrongEntitlementLease := newSignedLease(t, privateKey, secret, now, true, []string{"another-entitlement"},
		now.Add(time.Hour), now.Add(2*time.Minute))
	expiredLease := newSignedLease(t, privateKey, secret, now.Add(-10*time.Minute), true, nil,
		now.Add(time.Hour), now.Add(-time.Minute))
	malformedAny, err := anypb.New(structpb.NewStringValue(testEvidenceCanary))
	require.NoError(t, err)

	testCases := []struct {
		name       string
		response   *databroker.GetResponse
		getErr     error
		mutate     func(*Consumer)
		authority  func(testing.TB) ManagedPostgresAuthority
		wantNoCall bool
	}{
		{name: "transport error", getErr: errors.New(testTransportCanary)},
		{name: "missing response"},
		{name: "missing record", response: &databroker.GetResponse{}},
		{name: "deleted record", response: &databroker.GetResponse{Record: func() *databroker.Record {
			r := leaseRecord(t, validLease)
			r.DeletedAt = timestamppb.New(now)
			return r
		}()}},
		{name: "wrong type", response: &databroker.GetResponse{Record: func() *databroker.Record {
			r := leaseRecord(t, validLease)
			r.Type = "type.googleapis.com/attacker.Record"
			return r
		}()}},
		{name: "wrong id", response: &databroker.GetResponse{Record: func() *databroker.Record {
			r := leaseRecord(t, validLease)
			r.Id = "attacker-record"
			return r
		}()}},
		{name: "malformed evidence", response: &databroker.GetResponse{Record: &databroker.Record{
			Type: licenseproof.RecordTypeURL, Id: licenseproof.RecordID, Data: malformedAny,
		}}},
		{name: "unsigned capability cannot replace missing signed metadata", response: &databroker.GetResponse{Record: leaseRecord(t, missingMetadataLease)}},
		{name: "wrong signed entitlement", response: &databroker.GetResponse{Record: leaseRecord(t, wrongEntitlementLease)}},
		{name: "expired evidence", response: &databroker.GetResponse{Record: leaseRecord(t, expiredLease)}},
		{name: "wrong decrypt key", response: &databroker.GetResponse{Record: leaseRecord(t, validLease)}, authority: func(t testing.TB) ManagedPostgresAuthority {
			return testAuthority(t, []byte(testWrongSecretCanary))
		}},
		{name: "missing runtime authority", wantNoCall: true, authority: func(testing.TB) ManagedPostgresAuthority {
			return ManagedPostgresAuthority{}
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := mock_databroker.NewMockDataBrokerServiceClient(gomock.NewController(t))
			if !tc.wantNoCall {
				client.EXPECT().Get(gomock.Any(), gomock.Eq(&databroker.GetRequest{
					Type: licenseproof.RecordTypeURL,
					Id:   licenseproof.RecordID,
				})).Return(tc.response, tc.getErr)
			}
			consumer := testConsumer(publicKey, now, client)
			if tc.mutate != nil {
				tc.mutate(consumer)
			}

			authority := testAuthority(t, secret)
			if tc.authority != nil {
				authority = tc.authority(t)
			}
			expiresAt, err := consumer.VerifyManagedPostgres(context.Background(), authority)
			assert.True(t, expiresAt.IsZero())
			require.ErrorIs(t, err, ErrDenied)
			var denial DenialError
			require.ErrorAs(t, err, &denial)
			assert.Equal(t, "enterprise capability denied", err.Error())
			for _, canary := range []string{
				testLicenseCanary, testConfigSecretCanary, testWrongSecretCanary, testTransportCanary, testEvidenceCanary,
			} {
				assert.NotContains(t, fmt.Sprint(err), canary)
			}
		})
	}
}

func TestManagedPostgresAuthorityIsImmutable(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secret := []byte(testConfigSecretCanary)
	lease := newSignedLease(t, privateKey, secret, now, true, nil,
		now.Add(time.Hour), now.Add(2*time.Minute))

	client := mock_databroker.NewMockDataBrokerServiceClient(gomock.NewController(t))
	client.EXPECT().Get(gomock.Any(), gomock.Any()).Return(
		&databroker.GetResponse{Record: leaseRecord(t, lease)}, nil)
	consumer := testConsumer(publicKey, now, client)
	authority, err := NewManagedPostgresAuthority(testInstallation, secret)
	require.NoError(t, err)
	copy(secret, []byte(testWrongSecretCanary))

	_, err = consumer.VerifyManagedPostgres(t.Context(), authority)
	require.NoError(t, err)
}

type staticClientProvider struct {
	client databroker.DataBrokerServiceClient
}

func (p staticClientProvider) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return p.client
}

func testConsumer(
	publicKey ed25519.PublicKey,
	now time.Time,
	client databroker.DataBrokerServiceClient,
) *Consumer {
	consumer := NewConsumer(staticClientProvider{client: client})
	consumer.publicKey = publicKey
	consumer.accountID = testAccount
	consumer.productID = testProduct
	consumer.apiHost = testHost
	consumer.apiScheme = "https"
	consumer.now = func() time.Time { return now }
	return consumer
}

func testAuthority(t testing.TB, secret []byte) ManagedPostgresAuthority {
	t.Helper()
	authority, err := NewManagedPostgresAuthority(testInstallation, secret)
	require.NoError(t, err)
	return authority
}

func leaseRecord(t *testing.T, lease *enterprisepb.CapabilityLease) *databroker.Record {
	t.Helper()
	data, err := anypb.New(lease)
	require.NoError(t, err)
	return &databroker.Record{Type: licenseproof.RecordTypeURL, Id: licenseproof.RecordID, Data: data}
}

func newSignedLease(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	secret []byte,
	responseTime time.Time,
	managedMetadata bool,
	entitlements []string,
	licenseExpiry time.Time,
	leaseExpiry time.Time,
) *enterprisepb.CapabilityLease {
	t.Helper()
	const validationNonce = uint64(42)
	scope := map[string]any{
		"fingerprint": testInstallation,
		"product":     testProduct,
	}
	if entitlements != nil {
		scope["entitlements"] = entitlements
	}
	body, err := json.Marshal(map[string]any{
		"meta": map[string]any{
			"valid": true,
			"code":  "VALID",
			"nonce": validationNonce,
			"scope": scope,
		},
		"data": map[string]any{
			"attributes": map[string]any{
				"key":      testLicenseCanary,
				"expiry":   licenseExpiry.Format(time.RFC3339),
				"metadata": map[string]any{licenseproof.ManagedPostgresMetadataKey: managedMetadata},
			},
		},
	})
	require.NoError(t, err)
	rawURL := fmt.Sprintf("https://%s/v1/accounts/%s/licenses/license-id/actions/validate",
		testHost, url.PathEscape(testAccount))
	digestBytes := sha256.Sum256(body)
	digest := "sha-256=" + base64.StdEncoding.EncodeToString(digestBytes[:])
	date := responseTime.Format(time.RFC1123)
	message := fmt.Sprintf("(request-target): post %s\nhost: %s\ndate: %s\ndigest: %s",
		"/v1/accounts/"+url.PathEscape(testAccount)+"/licenses/license-id/actions/validate", testHost, date, digest)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(message)))
	response := licenseproof.NewResponse("POST", rawURL, body, date, digest,
		fmt.Sprintf(`keyid="key",algorithm="ed25519",signature="%s"`, signature))
	evidence, err := licenseproof.Seal(secret, testInstallation, validationNonce, response)
	require.NoError(t, err)
	lease, err := licenseproof.NewLease(testInstallation,
		[]enterprisepb.Capability{enterprisepb.Capability_CAPABILITY_POSTGRES_MANAGED_CREDENTIALS},
		leaseExpiry, evidence)
	require.NoError(t, err)
	return lease
}

func signedOfflineKey(t *testing.T, privateKey ed25519.PrivateKey, now time.Time) string {
	t.Helper()
	dataset, err := json.Marshal(map[string]any{
		"product": map[string]any{"id": testProduct},
		"license": map[string]any{
			"created": now.Add(-time.Hour),
			"expires": now.Add(time.Hour),
			"metadata": map[string]any{
				"allowOfflineVerification":              true,
				licenseproof.ManagedPostgresMetadataKey: true,
				"canary":                                testLicenseCanary,
			},
		},
	})
	require.NoError(t, err)
	encodedDataset := base64.URLEncoding.EncodeToString(dataset)
	signingData := "key/" + encodedDataset
	return signingData + "." + base64.URLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(signingData)))
}
