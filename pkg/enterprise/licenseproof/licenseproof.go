// Package licenseproof encrypts and verifies vendor-signed Enterprise license
// evidence transported between Pomerium Console and Pomerium Core.
package licenseproof

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/types/known/timestamppb"

	enterprisepb "github.com/pomerium/pomerium/pkg/grpc/enterprise"
)

const (
	// EvidenceVersion is the only encrypted evidence format currently supported.
	EvidenceVersion uint32 = 1
	// KeygenAccountID is Pomerium's public Keygen account identifier.
	KeygenAccountID = "49b1ca18-7382-44ff-9085-8c9a3e4502dc"
	// KeygenProductID is Pomerium's public Keygen product identifier.
	KeygenProductID = "cc2870b7-48a6-4581-bc6b-65699e3ce8df"
	// KeygenResponseSigningPublicKey is the public Ed25519 response-signing key.
	KeygenResponseSigningPublicKey = "b8a500de15fa440cc10748ca215bb02c5b772e7f23ec040f97ae013b3c9d7b1f" // #nosec G101
	// ManagedPostgresMetadataKey is the signed license metadata key granting
	// managed PostgreSQL access.
	ManagedPostgresMetadataKey = "postgresManagedAccess"
	// ManagedPostgresEntitlement is the Keygen entitlement required when a
	// validation response contains an explicit signed entitlement scope.
	ManagedPostgresEntitlement = "postgres-managed-credentials"

	// RecordID is the stable DataBroker record ID used for a capability lease.
	RecordID = "pomerium-console-license-capabilities"
	// RecordTypeURL is the DataBroker type URL for capability lease records.
	RecordTypeURL = "type.googleapis.com/pomerium.enterprise.CapabilityLease"

	keySize           = 32
	defaultMaxAge     = 5 * time.Minute
	defaultFutureSkew = 30 * time.Second
	keygenAPIHost     = "api.keygen.sh"
	keygenAPIScheme   = "https"
	keyDerivationInfo = "pomerium-enterprise-capability-proof/v1"
)

var (
	// ErrInvalidEnvelope indicates malformed or unsupported encrypted evidence.
	ErrInvalidEnvelope = errors.New("invalid encrypted license evidence")
	// ErrDecrypt indicates that evidence could not be authenticated and decrypted.
	ErrDecrypt = errors.New("could not decrypt license evidence")
	// ErrInvalidResponse indicates a malformed or unexpected Keygen response.
	ErrInvalidResponse = errors.New("invalid signed license response")
	// ErrInvalidSignature indicates failed Keygen digest or signature verification.
	ErrInvalidSignature = errors.New("invalid license response signature")
	// ErrStaleResponse indicates that otherwise valid evidence is too old.
	ErrStaleResponse = errors.New("signed license response is stale")
	// ErrFutureResponse indicates a response date beyond the permitted clock skew.
	ErrFutureResponse = errors.New("signed license response date is in the future")
	// ErrInvalidClaims indicates that signed validation claims do not match the consumer.
	ErrInvalidClaims = errors.New("invalid signed license claims")
)

// Response is a redacted in-memory representation of a signed Keygen response.
// Its body may contain a license key and must never be logged.
type Response struct {
	method    string
	url       string
	body      []byte
	date      string
	digest    string
	signature string
}

// NewResponse copies the response material required for independent signature
// verification. Header values should come from Date, Digest, and
// Keygen-Signature respectively.
func NewResponse(method, rawURL string, body []byte, date, digest, signature string) *Response {
	return &Response{
		method:    method,
		url:       rawURL,
		body:      append([]byte(nil), body...),
		date:      date,
		digest:    digest,
		signature: signature,
	}
}

// String deliberately does not expose signed response material.
func (Response) String() string { return "[redacted Keygen license response]" }

type wireResponse struct {
	Method    string `json:"method"`
	URL       string `json:"url"`
	Body      []byte `json:"body"`
	Date      string `json:"date"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

// Claims are the non-secret claims extracted from a verified Keygen validation
// response. Metadata may contain customer-defined values and is redacted by
// String.
type Claims struct {
	ValidationCode   string
	ValidationNonce  uint64
	ProductID        string
	InstallationID   string
	Entitlements     []string
	LicenseExpiresAt *time.Time
	Metadata         map[string]json.RawMessage
}

// String deliberately omits metadata and other response contents.
func (c Claims) String() string {
	return fmt.Sprintf("license claims{code=%s product-bound=%t installation-bound=%t expires=%t}",
		c.ValidationCode, c.ProductID != "", c.InstallationID != "", c.LicenseExpiresAt != nil)
}

// MetadataBool reads a boolean license metadata value without including its
// contents in any returned error.
func (c Claims) MetadataBool(name string) (bool, error) {
	raw, ok := c.Metadata[name]
	if !ok {
		return false, nil
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, ErrInvalidClaims
	}
	return value, nil
}

// ClaimsValidator applies product-specific checks to already authenticated
// claims. It must not treat unverified CapabilityLease fields as authority.
type ClaimsValidator func(Claims) error

// VerifyOptions defines the consumer-bound expectations for a signed response.
type VerifyOptions struct {
	PublicKey       ed25519.PublicKey
	AccountID       string
	ProductID       string
	InstallationID  string
	ValidationNonce uint64
	Now             func() time.Time
	MaxAge          time.Duration
	FutureSkew      time.Duration
	APIHost         string
	APIScheme       string
	Validate        ClaimsValidator
}

// Verified contains authenticated claims and their maximum usable lifetime.
type Verified struct {
	Claims    Claims
	ExpiresAt time.Time
}

// PublicKey decodes a hex-encoded Keygen Ed25519 public key.
func PublicKey(value string) (ed25519.PublicKey, error) {
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, ErrInvalidSignature
	}
	return ed25519.PublicKey(key), nil
}

// Seal encrypts a signed response for one installation. The validation nonce
// is authenticated both by the AEAD envelope and the signed response claims.
func Seal(secret []byte, installationID string, validationNonce uint64, response *Response) (*enterprisepb.EncryptedKeygenEvidence, error) {
	return seal(rand.Reader, secret, installationID, validationNonce, response)
}

func seal(random io.Reader, secret []byte, installationID string, validationNonce uint64, response *Response) (*enterprisepb.EncryptedKeygenEvidence, error) {
	if len(secret) == 0 || installationID == "" || validationNonce == 0 || response == nil {
		return nil, ErrInvalidEnvelope
	}

	plaintext, err := json.Marshal(wireResponse{
		Method: response.method, URL: response.url, Body: response.body,
		Date: response.date, Digest: response.digest, Signature: response.signature,
	})
	if err != nil {
		return nil, ErrInvalidEnvelope
	}

	aead, err := newAEAD(secret, installationID)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, ErrInvalidEnvelope
	}
	aad := associatedData(installationID, validationNonce)
	return &enterprisepb.EncryptedKeygenEvidence{
		Version:         EvidenceVersion,
		ValidationNonce: validationNonce,
		Nonce:           nonce,
		Ciphertext:      aead.Seal(nil, nonce, plaintext, aad),
	}, nil
}

// Open decrypts evidence but does not authenticate the Keygen response. Most
// consumers should call OpenAndVerify instead.
func Open(secret []byte, installationID string, evidence *enterprisepb.EncryptedKeygenEvidence) (*Response, error) {
	if len(secret) == 0 || installationID == "" || evidence == nil ||
		evidence.GetVersion() != EvidenceVersion || evidence.GetValidationNonce() == 0 {
		return nil, ErrInvalidEnvelope
	}
	aead, err := newAEAD(secret, installationID)
	if err != nil {
		return nil, err
	}
	if len(evidence.GetNonce()) != aead.NonceSize() || len(evidence.GetCiphertext()) == 0 {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(nil, evidence.GetNonce(), evidence.GetCiphertext(), associatedData(installationID, evidence.GetValidationNonce()))
	if err != nil {
		return nil, ErrDecrypt
	}
	var wire wireResponse
	if err := json.Unmarshal(plaintext, &wire); err != nil {
		return nil, ErrInvalidEnvelope
	}
	return NewResponse(wire.Method, wire.URL, wire.Body, wire.Date, wire.Digest, wire.Signature), nil
}

// OpenAndVerify decrypts evidence, verifies the Keygen response signature and
// consumer-bound claims, and returns the maximum evidence lifetime.
func OpenAndVerify(secret []byte, evidence *enterprisepb.EncryptedKeygenEvidence, opts VerifyOptions) (*Verified, error) {
	if opts.ValidationNonce == 0 || evidence == nil || evidence.GetValidationNonce() != opts.ValidationNonce {
		return nil, ErrInvalidClaims
	}
	response, err := Open(secret, opts.InstallationID, evidence)
	if err != nil {
		return nil, err
	}
	return Verify(response, opts)
}

// VerifyLease verifies the encrypted vendor evidence and applies the lease's
// declared expiration only as an additional upper bound. It deliberately does
// not treat the declared capability list as proof of entitlement; callers must
// enforce capabilities through VerifyOptions.Validate over signed claims.
func VerifyLease(secret []byte, lease *enterprisepb.CapabilityLease, opts VerifyOptions) (*Verified, error) {
	if lease == nil || lease.GetInstallationId() == "" || lease.GetInstallationId() != opts.InstallationID ||
		lease.GetKeygenEvidence() == nil || lease.GetOfflineKeyEvidence() != nil || lease.GetExpiresAt() == nil ||
		lease.GetExpiresAt().CheckValid() != nil {
		return nil, ErrInvalidEnvelope
	}
	opts.ValidationNonce = lease.GetKeygenEvidence().GetValidationNonce()
	verified, err := OpenAndVerify(secret, lease.GetKeygenEvidence(), opts)
	if err != nil {
		return nil, err
	}
	leaseExpiry := lease.GetExpiresAt().AsTime()
	if leaseExpiry.Before(verified.ExpiresAt) {
		verified.ExpiresAt = leaseExpiry
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	if !verified.ExpiresAt.After(now()) {
		return nil, ErrStaleResponse
	}
	return verified, nil
}

// NewLease creates the transport contract for encrypted evidence. The
// capability list remains an untrusted declaration until VerifyLease validates
// the vendor-signed claims with a product-specific hook.
func NewLease(installationID string, capabilities []enterprisepb.Capability, expiresAt time.Time, evidence *enterprisepb.EncryptedKeygenEvidence) (*enterprisepb.CapabilityLease, error) {
	if installationID == "" || evidence == nil || expiresAt.IsZero() {
		return nil, ErrInvalidEnvelope
	}
	return &enterprisepb.CapabilityLease{
		InstallationId: installationID,
		Capabilities:   append([]enterprisepb.Capability(nil), capabilities...),
		ExpiresAt:      timestamppb.New(expiresAt),
		KeygenEvidence: evidence,
	}, nil
}

// Verify authenticates a signed Keygen validation response and its claims.
func Verify(response *Response, opts VerifyOptions) (*Verified, error) {
	if response == nil || len(opts.PublicKey) != ed25519.PublicKeySize ||
		opts.AccountID == "" || opts.ProductID == "" || opts.InstallationID == "" || opts.ValidationNonce == 0 {
		return nil, ErrInvalidResponse
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

	responseDate, err := verifySignature(response, opts, now(), maxAge, futureSkew)
	if err != nil {
		return nil, err
	}
	claims, err := extractClaims(response.body)
	if err != nil {
		return nil, err
	}
	if claims.ValidationCode != "VALID" || claims.ValidationNonce != opts.ValidationNonce ||
		claims.ProductID != opts.ProductID || claims.InstallationID != opts.InstallationID {
		return nil, ErrInvalidClaims
	}
	if opts.Validate != nil {
		if err := opts.Validate(claims); err != nil {
			return nil, ErrInvalidClaims
		}
	}

	expiresAt := responseDate.Add(maxAge)
	if claims.LicenseExpiresAt != nil && claims.LicenseExpiresAt.Before(expiresAt) {
		expiresAt = *claims.LicenseExpiresAt
	}
	if !expiresAt.After(now()) {
		return nil, ErrStaleResponse
	}
	return &Verified{Claims: claims, ExpiresAt: expiresAt}, nil
}

func newAEAD(secret []byte, installationID string) (cipher.AEAD, error) {
	if len(secret) == 0 || installationID == "" {
		return nil, ErrInvalidEnvelope
	}
	key := make([]byte, keySize)
	reader := hkdf.New(sha256.New, secret, []byte(installationID), []byte(keyDerivationInfo))
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

func associatedData(installationID string, validationNonce uint64) []byte {
	buf := make([]byte, 0, len(keyDerivationInfo)+len(RecordID)+len(installationID)+32)
	buf = append(buf, keyDerivationInfo...)
	buf = append(buf, 0)
	buf = append(buf, RecordID...)
	buf = append(buf, 0)
	buf = append(buf, installationID...)
	buf = append(buf, 0)
	buf = binary.BigEndian.AppendUint64(buf, validationNonce)
	return buf
}

func verifySignature(response *Response, opts VerifyOptions, now time.Time, maxAge, futureSkew time.Duration) (time.Time, error) {
	if strings.ToUpper(response.method) != "POST" || response.date == "" || response.digest == "" || response.signature == "" {
		return time.Time{}, ErrInvalidResponse
	}
	u, err := url.Parse(response.url)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return time.Time{}, ErrInvalidResponse
	}
	scheme := opts.APIScheme
	if scheme == "" {
		scheme = keygenAPIScheme
	}
	host := opts.APIHost
	if host == "" {
		host = keygenAPIHost
	}
	if u.Scheme != scheme || u.Host != host {
		return time.Time{}, ErrInvalidResponse
	}
	pathParts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(pathParts) != 7 || pathParts[0] != "v1" || pathParts[1] != "accounts" ||
		pathParts[2] != url.PathEscape(opts.AccountID) || pathParts[3] != "licenses" ||
		pathParts[4] == "" || pathParts[5] != "actions" || pathParts[6] != "validate" {
		return time.Time{}, ErrInvalidResponse
	}

	calculated := sha256.Sum256(response.body)
	expectedDigest := "sha-256=" + base64.StdEncoding.EncodeToString(calculated[:])
	if response.digest != expectedDigest {
		return time.Time{}, ErrInvalidSignature
	}
	responseDate, err := time.Parse(time.RFC1123, response.date)
	if err != nil {
		return time.Time{}, ErrInvalidResponse
	}
	if responseDate.After(now.Add(futureSkew)) {
		return time.Time{}, ErrFutureResponse
	}
	if now.Sub(responseDate) > maxAge {
		return time.Time{}, ErrStaleResponse
	}

	signature, err := signatureValue(response.signature)
	if err != nil {
		return time.Time{}, ErrInvalidSignature
	}
	message := fmt.Sprintf("(request-target): %s %s\nhost: %s\ndate: %s\ndigest: %s",
		strings.ToLower(response.method), u.Path, u.Host, response.date, response.digest)
	if !ed25519.Verify(opts.PublicKey, []byte(message), signature) {
		return time.Time{}, ErrInvalidSignature
	}
	return responseDate, nil
}

func signatureValue(header string) ([]byte, error) {
	var encoded string
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return nil, ErrInvalidSignature
		}
		if key == "signature" {
			encoded = strings.Trim(value, `"`)
		}
	}
	if encoded == "" {
		return nil, ErrInvalidSignature
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidSignature
	}
	return decoded, nil
}

func extractClaims(body []byte) (Claims, error) {
	var payload struct {
		Meta struct {
			Valid    bool        `json:"valid"`
			Code     string      `json:"code"`
			Constant string      `json:"constant"`
			Nonce    json.Number `json:"nonce"`
			Scope    struct {
				Product      string   `json:"product"`
				Fingerprint  string   `json:"fingerprint"`
				Fingerprints []string `json:"fingerprints"`
				Entitlements []string `json:"entitlements"`
			} `json:"scope"`
		} `json:"meta"`
		Data struct {
			Attributes struct {
				Expiry   *time.Time                 `json:"expiry"`
				Metadata map[string]json.RawMessage `json:"metadata"`
			} `json:"attributes"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil || !payload.Meta.Valid {
		return Claims{}, ErrInvalidClaims
	}
	validationCode := payload.Meta.Code
	if validationCode == "" {
		validationCode = payload.Meta.Constant
	}
	nonce, err := strconv.ParseUint(payload.Meta.Nonce.String(), 10, 64)
	if err != nil || nonce == 0 {
		return Claims{}, ErrInvalidClaims
	}
	installationID := payload.Meta.Scope.Fingerprint
	if installationID == "" && len(payload.Meta.Scope.Fingerprints) == 1 {
		installationID = payload.Meta.Scope.Fingerprints[0]
	}
	if installationID == "" {
		return Claims{}, ErrInvalidClaims
	}
	return Claims{
		ValidationCode:   validationCode,
		ValidationNonce:  nonce,
		ProductID:        payload.Meta.Scope.Product,
		InstallationID:   installationID,
		Entitlements:     append([]string(nil), payload.Meta.Scope.Entitlements...),
		LicenseExpiresAt: payload.Data.Attributes.Expiry,
		Metadata:         payload.Data.Attributes.Metadata,
	}, nil
}
