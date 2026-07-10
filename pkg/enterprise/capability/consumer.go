// Package capability verifies short-lived Enterprise capability leases from
// the authenticated DataBroker connection.
package capability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"slices"
	"time"

	"github.com/pomerium/pomerium/pkg/enterprise/licenseproof"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	enterprisepb "github.com/pomerium/pomerium/pkg/grpc/enterprise"
)

// DenialError is the deliberately generic error returned for every missing,
// invalid, expired, or unavailable capability. It never wraps configuration,
// transport, license, or evidence errors.
type DenialError struct{}

func (DenialError) Error() string { return "enterprise capability denied" }

// ErrDenied is returned whenever managed PostgreSQL capability evidence cannot
// be freshly fetched and verified.
var ErrDenied = DenialError{}

// ManagedPostgresVerifier is the minimal contract used at each managed
// PostgreSQL authorization boundary. A successful result is valid only until
// the returned expiry.
type ManagedPostgresVerifier interface {
	VerifyManagedPostgres(context.Context, ManagedPostgresAuthority) (time.Time, error)
}

// ManagedPostgresAuthority is the immutable installation authority associated
// with one published PostgreSQL runtime generation. Its key material is copied
// at construction so file-backed shared-secret rotation cannot change an
// already-published generation.
type ManagedPostgresAuthority struct {
	installationID string
	sharedKey      []byte
}

// NewManagedPostgresAuthority constructs an immutable verification authority.
func NewManagedPostgresAuthority(installationID string, sharedKey []byte) (ManagedPostgresAuthority, error) {
	if installationID == "" || len(sharedKey) == 0 {
		return ManagedPostgresAuthority{}, ErrDenied
	}
	return ManagedPostgresAuthority{
		installationID: installationID,
		sharedKey:      append([]byte(nil), sharedKey...),
	}, nil
}

// Equal reports whether two runtime generations use the same installation
// authority. It does not expose either authority's secret material.
func (a ManagedPostgresAuthority) Equal(other ManagedPostgresAuthority) bool {
	return a.installationID == other.installationID && bytes.Equal(a.sharedKey, other.sharedKey)
}

func (a ManagedPostgresAuthority) valid() bool {
	return a.installationID != "" && len(a.sharedKey) != 0
}

// DataBrokerClientProvider returns the current authenticated DataBroker client.
type DataBrokerClientProvider interface {
	GetDataBrokerServiceClient() databroker.DataBrokerServiceClient
}

// Consumer fetches and verifies capability evidence without caching it.
type Consumer struct {
	clients   DataBrokerClientProvider
	publicKey ed25519.PublicKey
	accountID string
	productID string
	apiHost   string
	apiScheme string
	now       func() time.Time
}

var keygenResponseSigningPublicKey = mustPublicKey(licenseproof.KeygenResponseSigningPublicKey)

// NewConsumer creates a capability consumer pinned to Pomerium's Keygen
// account, product, and response-signing key.
func NewConsumer(clients DataBrokerClientProvider) *Consumer {
	return &Consumer{
		clients:   clients,
		publicKey: append(ed25519.PublicKey(nil), keygenResponseSigningPublicKey...),
		accountID: licenseproof.KeygenAccountID,
		productID: licenseproof.KeygenProductID,
		now:       time.Now,
	}
}

func mustPublicKey(value string) ed25519.PublicKey {
	publicKey, err := licenseproof.PublicKey(value)
	if err != nil {
		panic("capability: invalid pinned Keygen response-signing public key")
	}
	return publicKey
}

// VerifyManagedPostgres fetches the one stable capability record and verifies
// its encrypted vendor evidence against the installation authority pinned to
// the serving PostgreSQL runtime generation. No DataBroker TTL, local toggle,
// extension state, or prior result is treated as authority.
func (c *Consumer) VerifyManagedPostgres(ctx context.Context, authority ManagedPostgresAuthority) (time.Time, error) {
	if c == nil || c.clients == nil || c.now == nil || ctx == nil || !authority.valid() {
		return time.Time{}, ErrDenied
	}
	client := c.clients.GetDataBrokerServiceClient()
	if client == nil {
		return time.Time{}, ErrDenied
	}
	response, err := client.Get(ctx, &databroker.GetRequest{
		Type: licenseproof.RecordTypeURL,
		Id:   licenseproof.RecordID,
	})
	if err != nil {
		return time.Time{}, ErrDenied
	}
	record := response.GetRecord()
	if record == nil || record.GetDeletedAt() != nil || record.GetType() != licenseproof.RecordTypeURL ||
		record.GetId() != licenseproof.RecordID || record.GetData() == nil {
		return time.Time{}, ErrDenied
	}
	var lease enterprisepb.CapabilityLease
	if err := record.GetData().UnmarshalTo(&lease); err != nil {
		return time.Time{}, ErrDenied
	}
	if (lease.GetKeygenEvidence() == nil) == (lease.GetOfflineKeyEvidence() == nil) {
		return time.Time{}, ErrDenied
	}
	if lease.GetOfflineKeyEvidence() != nil {
		// An offline signed key has no vendor-signed installation/fingerprint
		// claim. VerifyOfflineLease instead authenticates the Console-to-Core
		// envelope for this installation and enforces its short freshness bound.
		// The shared Keygen key is safe here because the signed domains are
		// prefix-disjoint: online evidence signs an HTTP-signature canonical
		// request, while offline keys sign data beginning with "key/".
		verified, err := licenseproof.VerifyOfflineLease(authority.sharedKey, &lease, authority.installationID,
			licenseproof.OfflineVerifyOptions{
				PublicKey: c.publicKey,
				ProductID: c.productID,
				Now:       c.now,
			})
		if err != nil || verified == nil || !verified.ExpiresAt.After(c.now()) {
			return time.Time{}, ErrDenied
		}
		return verified.ExpiresAt, nil
	}
	verified, err := licenseproof.VerifyLease(authority.sharedKey, &lease, licenseproof.VerifyOptions{
		PublicKey:      c.publicKey,
		AccountID:      c.accountID,
		ProductID:      c.productID,
		InstallationID: authority.installationID,
		Now:            c.now,
		APIHost:        c.apiHost,
		APIScheme:      c.apiScheme,
		Validate:       validateManagedPostgresClaims,
	})
	if err != nil || verified == nil || !verified.ExpiresAt.After(c.now()) {
		return time.Time{}, ErrDenied
	}
	return verified.ExpiresAt, nil
}

func validateManagedPostgresClaims(claims licenseproof.Claims) error {
	enabled, err := claims.MetadataBool(licenseproof.ManagedPostgresMetadataKey)
	if err != nil || !enabled {
		return licenseproof.ErrInvalidClaims
	}
	if len(claims.Entitlements) > 0 &&
		!slices.Contains(claims.Entitlements, licenseproof.ManagedPostgresEntitlement) {
		return licenseproof.ErrInvalidClaims
	}
	return nil
}
