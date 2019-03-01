package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"
import (
	"fmt"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// JWTSigner implements JWT signing according to JSON Web Token (JWT) RFC7519
// https://tools.ietf.org/html/rfc7519
type JWTSigner interface {
	SignJWT(string, string, string) (string, error)
}

// ES256Signer is struct containing the required fields to create a ES256 signed JSON Web Tokens
type ES256Signer struct {
	// User (sub) is unique, stable identifier for the user.
	// Use in place of the x-pomerium-authenticated-user-id header.
	User string `json:"sub,omitempty"`

	// Email (email) is a **custom** claim name identifier for the user email address.
	// Use in place of the x-pomerium-authenticated-user-email header.
	Email string `json:"email,omitempty"`

	// Groups (groups) is a **custom** claim name identifier for the user's groups.
	// Use in place of the x-pomerium-authenticated-user-groups header.
	Groups string `json:"groups,omitempty"`

	// Audience (aud) must be the destination of the upstream proxy locations.
	// e.g. `helloworld.corp.example.com`
	Audience jwt.Audience `json:"aud,omitempty"`
	// Issuer (iss) is the URL of the proxy.
	// e.g. `proxy.corp.example.com`
	Issuer string `json:"iss,omitempty"`
	// Expiry (exp) is the expiration time in seconds since the UNIX epoch.
	// Allow 1 minute for skew. The maximum lifetime of a token is 10 minutes + 2 * skew.
	Expiry jwt.NumericDate `json:"exp,omitempty"`
	// IssuedAt (iat) is the time is measured in seconds since the UNIX epoch.
	// Allow 1 minute for skew.
	IssuedAt jwt.NumericDate `json:"iat,omitempty"`
	// IssuedAt (nbf) is the time is measured in seconds since the UNIX epoch.
	// Allow 1 minute for skew.
	NotBefore jwt.NumericDate `json:"nbf,omitempty"`

	signer jose.Signer
}

// NewES256Signer creates an Elliptic Curve, NIST P-256 (aka secp256r1 aka prime256v1) JWT signer.
//
// RSA is not supported due to performance considerations of needing to sign each request.
// Go's P-256 is constant-time and SHA-256 is faster on 64-bit machines and immune
// to length extension attacks.
// See also:
// - https://cloud.google.com/iot/docs/how-tos/credentials/keys
func NewES256Signer(privKey []byte, audience string) (*ES256Signer, error) {
	key, err := DecodePrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("internal/cryptutil parsing key failed %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256, // ECDSA using P-256 and SHA-256
			Key:       key,
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, fmt.Errorf("internal/cryptutil new signer failed %v", err)
	}
	return &ES256Signer{
		Issuer:   "pomerium-proxy",
		Audience: jwt.Audience{audience},
		signer:   signer,
	}, nil
}

// SignJWT creates a signed JWT containing claims for the logged in
// user id (`sub`), email (`email`) and groups (`groups`).
func (s *ES256Signer) SignJWT(user, email, groups string) (string, error) {
	s.User = user
	s.Email = email
	s.Groups = groups
	now := time.Now()
	s.IssuedAt = *jwt.NewNumericDate(now)
	s.Expiry = *jwt.NewNumericDate(now.Add(jwt.DefaultLeeway))
	s.NotBefore = *jwt.NewNumericDate(now.Add(-1 * jwt.DefaultLeeway))
	rawJWT, err := jwt.Signed(s.signer).Claims(s).CompactSerialize()
	if err != nil {
		return "", err
	}
	return rawJWT, nil
}
