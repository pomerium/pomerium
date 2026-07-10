package licenseproof

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/types/known/timestamppb"

	enterprisepb "github.com/pomerium/pomerium/pkg/grpc/enterprise"
)

const (
	// OfflineEvidenceVersion is the only encrypted offline-key evidence format
	// currently supported.
	OfflineEvidenceVersion uint32 = 1

	offlineKeyDerivationInfo = "pomerium-enterprise-capability-offline-key/v1"
	offlineEvidenceType      = "keygen-ed25519-sign-offline-key"
	maxOfflineSignedKeySize  = 128 << 10
	maxOfflineDatasetSize    = 64 << 10
)

// ErrInvalidOfflineKey indicates malformed, incorrectly signed, or
// unsupported Keygen ED25519_SIGN key material.
var ErrInvalidOfflineKey = errors.New("invalid offline license key")

// OfflineVerifyOptions defines the pinned expectations for a Keygen
// ED25519_SIGN offline payload.
type OfflineVerifyOptions struct {
	PublicKey  ed25519.PublicKey
	ProductID  string
	Now        func() time.Time
	MaxAge     time.Duration
	FutureSkew time.Duration
}

// OfflineClaims are the non-secret claims authenticated by an offline signed
// key. Offline keys have no installation or fingerprint claim.
type OfflineClaims struct {
	ProductID        string
	CreatedAt        time.Time
	LicenseExpiresAt time.Time
}

// String deliberately omits payload metadata.
func (c OfflineClaims) String() string {
	return "offline license claims{product-bound=true expires=true}"
}

// VerifiedOffline contains independently verified offline claims and their
// maximum usable evidence lifetime.
type VerifiedOffline struct {
	Claims    OfflineClaims
	ExpiresAt time.Time
}

type offlineWireEvidence struct {
	IssuedAt  time.Time `json:"issued_at"`
	SignedKey string    `json:"signed_key"`
}

type offlineKeyPayload struct {
	Product struct {
		ID string `json:"id"`
	} `json:"product"`
	License struct {
		Created  time.Time  `json:"created"`
		Expires  *time.Time `json:"expires"`
		Metadata struct {
			AllowOfflineVerification bool `json:"allowOfflineVerification"`
			PostgresManagedAccess    bool `json:"postgresManagedAccess"`
		} `json:"metadata"`
	} `json:"license"`
}

// SealOfflineKey encrypts one already-signed offline key for one Core
// installation. The signed payload itself has no installation claim; the AEAD
// key and associated data prevent this ciphertext from being replayed for a
// different installation ID.
func SealOfflineKey(
	secret []byte,
	installationID string,
	issuedAt time.Time,
	signedKey string,
) (*enterprisepb.EncryptedOfflineKeyEvidence, error) {
	return sealOfflineKey(rand.Reader, secret, installationID, issuedAt, signedKey)
}

func sealOfflineKey(
	random io.Reader,
	secret []byte,
	installationID string,
	issuedAt time.Time,
	signedKey string,
) (*enterprisepb.EncryptedOfflineKeyEvidence, error) {
	if len(secret) == 0 || installationID == "" || issuedAt.IsZero() ||
		!validOfflineSignedKeyLength(signedKey) {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := json.Marshal(offlineWireEvidence{IssuedAt: issuedAt, SignedKey: signedKey})
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	aead, err := newOfflineAEAD(secret, installationID)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, ErrInvalidEnvelope
	}
	return &enterprisepb.EncryptedOfflineKeyEvidence{
		Version:    OfflineEvidenceVersion,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, offlineAssociatedData(installationID)),
	}, nil
}

// VerifyOfflineSignedKey independently verifies the Keygen ED25519_SIGN key
// and the existing Pomerium offline payload contract.
func VerifyOfflineSignedKey(signedKey string, opts OfflineVerifyOptions) (*OfflineClaims, error) {
	if len(opts.PublicKey) != ed25519.PublicKeySize || opts.ProductID == "" ||
		!validOfflineSignedKeyLength(signedKey) {
		return nil, ErrInvalidOfflineKey
	}
	dataset, err := verifyAndDecodeOfflineKey(signedKey, opts.PublicKey)
	if err != nil {
		return nil, err
	}
	var payload offlineKeyPayload
	decoder := json.NewDecoder(bytes.NewReader(dataset))
	if err := decoder.Decode(&payload); err != nil {
		return nil, ErrInvalidOfflineKey
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, ErrInvalidOfflineKey
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	futureSkew := opts.FutureSkew
	if futureSkew <= 0 || futureSkew > defaultFutureSkew {
		futureSkew = defaultFutureSkew
	}
	currentTime := now()
	if payload.Product.ID != opts.ProductID || payload.License.Created.IsZero() ||
		payload.License.Created.After(currentTime.Add(futureSkew)) || payload.License.Expires == nil ||
		!payload.License.Expires.After(payload.License.Created) ||
		!payload.License.Expires.After(currentTime) ||
		!payload.License.Metadata.AllowOfflineVerification ||
		!payload.License.Metadata.PostgresManagedAccess {
		return nil, ErrInvalidClaims
	}
	return &OfflineClaims{
		ProductID:        payload.Product.ID,
		CreatedAt:        payload.License.Created,
		LicenseExpiresAt: *payload.License.Expires,
	}, nil
}

// VerifyOfflineLease authenticates the installation-bound envelope, verifies
// the signed offline license, and treats the declared lease expiry only as an
// additional upper bound.
func VerifyOfflineLease(
	secret []byte,
	lease *enterprisepb.CapabilityLease,
	installationID string,
	opts OfflineVerifyOptions,
) (*VerifiedOffline, error) {
	if lease == nil || lease.GetInstallationId() == "" || lease.GetInstallationId() != installationID ||
		lease.GetKeygenEvidence() != nil || lease.GetOfflineKeyEvidence() == nil ||
		lease.GetExpiresAt() == nil || lease.GetExpiresAt().CheckValid() != nil {
		return nil, ErrInvalidEnvelope
	}
	wire, err := openOfflineKey(secret, installationID, lease.GetOfflineKeyEvidence())
	if err != nil {
		return nil, err
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	maxAge := opts.MaxAge
	if maxAge <= 0 || maxAge > defaultMaxAge {
		maxAge = defaultMaxAge
	}
	futureSkew := opts.FutureSkew
	if futureSkew <= 0 || futureSkew > defaultFutureSkew {
		futureSkew = defaultFutureSkew
	}
	currentTime := now()
	if wire.IssuedAt.After(currentTime.Add(futureSkew)) {
		return nil, ErrFutureResponse
	}
	if currentTime.Sub(wire.IssuedAt) > maxAge {
		return nil, ErrStaleResponse
	}
	opts.Now = func() time.Time { return currentTime }
	claims, err := VerifyOfflineSignedKey(wire.SignedKey, opts)
	if err != nil {
		return nil, err
	}
	expiresAt := wire.IssuedAt.Add(maxAge)
	if claims.LicenseExpiresAt.Before(expiresAt) {
		expiresAt = claims.LicenseExpiresAt
	}
	leaseExpiry := lease.GetExpiresAt().AsTime()
	if leaseExpiry.Before(expiresAt) {
		expiresAt = leaseExpiry
	}
	if !expiresAt.After(currentTime) {
		return nil, ErrStaleResponse
	}
	return &VerifiedOffline{Claims: *claims, ExpiresAt: expiresAt}, nil
}

// NewOfflineLease creates the transport contract for encrypted offline key
// evidence. Its declared expiration may only shorten authenticated evidence.
func NewOfflineLease(
	installationID string,
	capabilities []enterprisepb.Capability,
	expiresAt time.Time,
	evidence *enterprisepb.EncryptedOfflineKeyEvidence,
) (*enterprisepb.CapabilityLease, error) {
	if installationID == "" || evidence == nil || expiresAt.IsZero() {
		return nil, ErrInvalidEnvelope
	}
	return &enterprisepb.CapabilityLease{
		InstallationId:     installationID,
		Capabilities:       append([]enterprisepb.Capability(nil), capabilities...),
		ExpiresAt:          timestamppb.New(expiresAt),
		OfflineKeyEvidence: evidence,
	}, nil
}

func openOfflineKey(
	secret []byte,
	installationID string,
	evidence *enterprisepb.EncryptedOfflineKeyEvidence,
) (*offlineWireEvidence, error) {
	if len(secret) == 0 || installationID == "" || evidence == nil ||
		evidence.GetVersion() != OfflineEvidenceVersion {
		return nil, ErrInvalidEnvelope
	}
	aead, err := newOfflineAEAD(secret, installationID)
	if err != nil {
		return nil, err
	}
	if len(evidence.GetNonce()) != aead.NonceSize() || len(evidence.GetCiphertext()) == 0 {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(nil, evidence.GetNonce(), evidence.GetCiphertext(), offlineAssociatedData(installationID))
	if err != nil {
		return nil, ErrDecrypt
	}
	var wire offlineWireEvidence
	if err := json.Unmarshal(plaintext, &wire); err != nil || wire.IssuedAt.IsZero() ||
		!validOfflineSignedKeyLength(wire.SignedKey) {
		return nil, ErrInvalidEnvelope
	}
	return &wire, nil
}

func verifyAndDecodeOfflineKey(signedKey string, publicKey ed25519.PublicKey) ([]byte, error) {
	if strings.Count(signedKey, ".") != 1 {
		return nil, ErrInvalidOfflineKey
	}
	signingData, encodedSignature, ok := strings.Cut(signedKey, ".")
	if !ok || strings.Count(signingData, "/") != 1 {
		return nil, ErrInvalidOfflineKey
	}
	prefix, encodedDataset, ok := strings.Cut(signingData, "/")
	if !ok || prefix != "key" || encodedDataset == "" || encodedSignature == "" {
		return nil, ErrInvalidOfflineKey
	}
	dataset, err := decodeBase64URL(encodedDataset, maxOfflineDatasetSize)
	if err != nil {
		return nil, ErrInvalidOfflineKey
	}
	signature, err := decodeBase64URL(encodedSignature, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalidOfflineKey
	}
	if !ed25519.Verify(publicKey, []byte("key/"+encodedDataset), signature) {
		return nil, ErrInvalidOfflineKey
	}
	return dataset, nil
}

func decodeBase64URL(value string, maxDecodedSize int) ([]byte, error) {
	if value == "" || strings.ContainsAny(value, "\r\n\t ") ||
		base64.RawURLEncoding.DecodedLen(len(strings.TrimRight(value, "="))) > maxDecodedSize {
		return nil, ErrInvalidOfflineKey
	}
	var (
		decoded []byte
		err     error
	)
	if strings.Contains(value, "=") {
		if strings.Contains(strings.TrimRight(value, "="), "=") {
			return nil, ErrInvalidOfflineKey
		}
		decoded, err = base64.URLEncoding.Strict().DecodeString(value)
	} else {
		decoded, err = base64.RawURLEncoding.Strict().DecodeString(value)
	}
	if err != nil || len(decoded) > maxDecodedSize {
		return nil, ErrInvalidOfflineKey
	}
	return decoded, nil
}

func validOfflineSignedKeyLength(signedKey string) bool {
	return signedKey != "" && len(signedKey) <= maxOfflineSignedKeySize && strings.TrimSpace(signedKey) == signedKey
}

func newOfflineAEAD(secret []byte, installationID string) (cipher.AEAD, error) {
	if len(secret) == 0 || installationID == "" {
		return nil, ErrInvalidEnvelope
	}
	key := make([]byte, keySize)
	reader := hkdf.New(sha256.New, secret, []byte(installationID), []byte(offlineKeyDerivationInfo))
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, ErrInvalidEnvelope
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	return aead, nil
}

func offlineAssociatedData(installationID string) []byte {
	parts := []string{
		offlineKeyDerivationInfo,
		RecordTypeURL,
		RecordID,
		offlineEvidenceType,
		installationID,
	}
	return []byte(strings.Join(parts, "\x00"))
}
