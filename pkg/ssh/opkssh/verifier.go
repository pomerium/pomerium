// Copyright (c) 2024 Pomerium, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package opkssh verifies OpenPubkey PK Tokens carried by SSH certificates
// on Pomerium's native SSH listener. See ENG-2689.
//
// Validated: OIDC signature, issuer, audience, expiry, CIC commitment binding
// (nonce, signature, key binding), and SSH certificate time window
// (ValidAfter/ValidBefore).
//
// Not validated: COS (cosigner) segments are accepted but not verified.
package opkssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"
)

// opkSSHCertExtension is the certificate extension opkssh uses to embed the
// compact-serialized PK Token. Source: openpubkey/opkssh sshcert/sshcert.go.
const opkSSHCertExtension = "openpubkey-pkt"

// ErrNotOPKSSHKey indicates the key is not an opkssh user certificate; callers should fall through to other auth methods.
var ErrNotOPKSSHKey = errors.New("opkssh: not an opkssh public key")

// ErrInvalidPKToken indicates the extension is present but the PK Token payload is malformed.
var ErrInvalidPKToken = errors.New("opkssh: invalid PK Token")

// ErrCICBindingFailed indicates a CIC commitment binding validation failure.
var ErrCICBindingFailed = errors.New("opkssh: CIC binding failed")

// Identity is the verified identity returned by Verify.
type Identity struct {
	Issuer     string
	Subject    string
	Email      string
	Audience   []string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RawIDToken string
	Claims     map[string]any
}

// Verifier validates opkssh SSH certificates against a configured issuer and
// client ID allow-list.
type Verifier struct {
	issuer    string
	clientIDs []string
	provider  atomic.Pointer[oidc.Provider]
	sf        singleflight.Group
}

// NewVerifier returns a Verifier that validates the PK Token's OIDC layer,
// CIC commitment binding, and SSH certificate time window.
func NewVerifier(issuer string, clientIDs []string) (*Verifier, error) {
	if issuer == "" {
		return nil, errors.New("opkssh: issuer is required")
	}
	if len(clientIDs) == 0 {
		return nil, errors.New("opkssh: client IDs must not be empty")
	}
	return &Verifier{issuer: issuer, clientIDs: append([]string(nil), clientIDs...)}, nil
}

// resolveProvider lazily discovers the OIDC provider, deduplicating concurrent
// first-time callers via singleflight and never caching an error (so a
// transient DNS blip doesn't wedge the verifier until process restart).
func (v *Verifier) resolveProvider(ctx context.Context) (*oidc.Provider, error) {
	if p := v.provider.Load(); p != nil {
		return p, nil
	}
	res, err, _ := v.sf.Do("discover", func() (any, error) {
		if p := v.provider.Load(); p != nil {
			return p, nil
		}
		p, err := oidc.NewProvider(ctx, v.issuer)
		if err != nil {
			return nil, fmt.Errorf("opkssh: discover issuer %q: %w", v.issuer, err)
		}
		v.provider.Store(p)
		return p, nil
	})
	if err != nil {
		return nil, err
	}
	return res.(*oidc.Provider), nil
}

// Verify validates the PK Token carried in the SSH certificate extension
// against the configured issuer and client ID allow-list, verifies the CIC
// commitment binding, and checks the certificate time window.
func (v *Verifier) Verify(ctx context.Context, key ssh.PublicKey) (*Identity, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert {
		return nil, ErrNotOPKSSHKey
	}

	now := uint64(time.Now().Unix())
	if now < cert.ValidAfter {
		return nil, fmt.Errorf("opkssh: certificate is not yet valid")
	}
	if cert.ValidBefore != ssh.CertTimeInfinity && now >= cert.ValidBefore {
		return nil, fmt.Errorf("opkssh: certificate has expired")
	}

	pktCompact, ok := cert.Extensions[opkSSHCertExtension]
	if !ok {
		return nil, ErrNotOPKSSHKey
	}
	opJWS, err := extractOPJWSFromCompact(pktCompact)
	if err != nil {
		return nil, err
	}
	provider, err := v.resolveProvider(ctx)
	if err != nil {
		return nil, err
	}
	// Audience is enforced below against the allow-list; go-oidc's single-
	// client-id check is too narrow for multi-client opkssh deployments.
	idToken, err := provider.VerifierContext(ctx, &oidc.Config{SkipClientIDCheck: true}).Verify(ctx, opJWS)
	if err != nil {
		return nil, fmt.Errorf("opkssh: verify OP token: %w", err)
	}
	matched := false
	for _, a := range idToken.Audience {
		if slices.Contains(v.clientIDs, a) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("opkssh: audience %v not in allowed client IDs", idToken.Audience)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("opkssh: decode claims: %w", err)
	}

	nonce, _ := claims["nonce"].(string)
	if nonce == "" {
		return nil, fmt.Errorf("%w: missing nonce claim", ErrCICBindingFailed)
	}
	if err := verifyCICBinding(pktCompact, nonce, cert.Key); err != nil {
		return nil, err
	}

	email, _ := claims["email"].(string)
	return &Identity{
		Issuer:     idToken.Issuer,
		Subject:    idToken.Subject,
		Email:      email,
		Audience:   append([]string(nil), idToken.Audience...),
		IssuedAt:   idToken.IssuedAt,
		ExpiresAt:  idToken.Expiry,
		RawIDToken: opJWS,
		Claims:     claims,
	}, nil
}

// cicHeader is the decoded CIC protected header.
type cicHeader struct {
	Typ string          `json:"typ"`
	Alg string          `json:"alg"`
	Upk jose.JSONWebKey `json:"upk"`
	Rz  string          `json:"rz"`
}

// verifyCICBinding validates the CIC (Client Instance Claims) commitment in the
// PK Token compact representation. It checks:
//   - nonce commitment (SHA3-256 of the CIC protected header matches the ID token nonce)
//   - CIC signature over (cicProtected || "." || payload) using the embedded UPK
//   - key binding (UPK matches the SSH certificate public key)
//
// COS (cosigner) segments beyond index 4 are accepted but not validated.
func verifyCICBinding(compact string, idTokenNonce string, certKey ssh.PublicKey) error {
	segs := strings.Split(compact, ":")
	if len(segs) < 5 {
		return fmt.Errorf("%w: missing CIC segments", ErrCICBindingFailed)
	}
	payload, cicProtected, cicSig := segs[0], segs[3], segs[4]

	// Strip optional .freshToken suffix from CIC signature.
	if i := strings.IndexByte(cicSig, '.'); i >= 0 {
		cicSig = cicSig[:i]
	}

	// Nonce commitment: H(cicProtected) == idTokenNonce.
	cicRaw, err := base64.RawURLEncoding.DecodeString(cicProtected)
	if err != nil {
		return fmt.Errorf("%w: decode CIC protected: %w", ErrCICBindingFailed, err)
	}
	hash := sha3.Sum256(cicRaw)
	commitment := base64.RawURLEncoding.EncodeToString(hash[:])
	if commitment != idTokenNonce {
		return fmt.Errorf("%w: nonce mismatch", ErrCICBindingFailed)
	}

	// Parse CIC header.
	var header cicHeader
	if err := json.Unmarshal(cicRaw, &header); err != nil {
		return fmt.Errorf("%w: unmarshal CIC header: %w", ErrCICBindingFailed, err)
	}
	if header.Typ != "CIC" {
		return fmt.Errorf("%w: unexpected typ %q", ErrCICBindingFailed, header.Typ)
	}
	switch header.Alg {
	case "ES256", "EdDSA":
	default:
		return fmt.Errorf("%w: unsupported alg %q", ErrCICBindingFailed, header.Alg)
	}
	if header.Rz == "" {
		return fmt.Errorf("%w: missing rz", ErrCICBindingFailed)
	}

	// CIC signature verification.
	jws := cicProtected + "." + payload + "." + cicSig
	signed, err := jose.ParseSigned(jws)
	if err != nil {
		return fmt.Errorf("%w: parse CIC JWS: %w", ErrCICBindingFailed, err)
	}
	if _, err := signed.Verify(header.Upk.Key); err != nil {
		return fmt.Errorf("%w: CIC signature invalid: %w", ErrCICBindingFailed, err)
	}

	// Key binding: UPK must match the SSH certificate key.
	cpk, ok := certKey.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("%w: SSH key does not expose CryptoPublicKey()", ErrCICBindingFailed)
	}
	if !publicKeysEqual(cpk.CryptoPublicKey(), header.Upk.Key) {
		return fmt.Errorf("%w: upk does not match SSH certificate key", ErrCICBindingFailed)
	}

	return nil
}

func publicKeysEqual(a, b any) bool {
	switch a := a.(type) {
	case *ecdsa.PublicKey:
		b, ok := b.(*ecdsa.PublicKey)
		return ok && a.Equal(b)
	case ed25519.PublicKey:
		b, ok := b.(ed25519.PublicKey)
		return ok && a.Equal(b)
	default:
		return false
	}
}

// extractOPJWSFromCompact parses an opkssh compact PK Token and reassembles
// the OP (OIDC) segment as a standard RFC-7515 compact JWS.
//
// Compact format: base64url(payload) ":" base64url(protected1) ":" base64url(sig1)
// [":" base64url(protected2) ":" base64url(sig2) ...] ["." fresh_id_token].
// This function extracts only the first (protected, sig) pair (the OP segment);
// CIC binding is validated separately by verifyCICBinding.
func extractOPJWSFromCompact(compact string) (string, error) {
	const maxCompactLen = 64 * 1024 // 64 KB; well above any real PK Token
	if len(compact) > maxCompactLen {
		return "", fmt.Errorf("%w: compact token exceeds %d bytes", ErrInvalidPKToken, maxCompactLen)
	}
	segs := strings.Split(compact, ":")
	if len(segs) < 3 {
		return "", fmt.Errorf("%w: need at least 3 compact segments, got %d", ErrInvalidPKToken, len(segs))
	}
	payload, opProtected, opSig := segs[0], segs[1], segs[2]
	// Strip optional fresh_id_token suffix glued to the signature.
	if i := strings.IndexByte(opSig, '.'); i >= 0 {
		opSig = opSig[:i]
	}
	if payload == "" || opProtected == "" || opSig == "" {
		return "", fmt.Errorf("%w: empty OP segment", ErrInvalidPKToken)
	}
	return opProtected + "." + payload + "." + opSig, nil
}
