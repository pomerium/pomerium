// Copyright (c) 2024 Pomerium, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package opkssh verifies OpenPubkey PK Tokens carried by SSH certificates
// on Pomerium's native SSH listener. See ENG-2689.
//
// SAFETY: this is a DRAFT verifier. It validates the OIDC (OP) segment of
// the PK Token but does NOT yet validate:
//
//   - The CIC commitment binding the token to the presented SSH key. Without
//     this check the verifier is replay-vulnerable: a captured valid ID
//     token can be repackaged onto a self-signed cert over any key.
//   - The SSH certificate's ValidAfter/ValidBefore window.
//   - A COS (cosigner) signature.
//
// To make the footgun loud the only public constructor is
// NewDraftVerifierWithoutCICBinding; production wiring must gate it behind
// an explicit runtime flag until those checks land.
package opkssh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/coreos/go-oidc/v3/oidc"
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

// Identity is the verified identity returned by Verify.
type Identity struct {
	Issuer  string
	Subject string
	Email   string
}

// Trust is the OIDC trust policy a Verifier enforces.
type Trust struct {
	Issuer    string
	ClientIDs []string
}

// Verifier validates opkssh SSH certificates against a Trust policy.
type Verifier struct {
	trust    Trust
	provider atomic.Pointer[oidc.Provider]
	sf       singleflight.Group
}

// NewDraftVerifierWithoutCICBinding returns a Verifier that validates the
// PK Token's OIDC layer only. The name is intentionally loud: the returned
// verifier is REPLAY-VULNERABLE without the CIC binding check that is still
// to be implemented.
func NewDraftVerifierWithoutCICBinding(trust Trust) (*Verifier, error) {
	if trust.Issuer == "" {
		return nil, errors.New("opkssh: trust.Issuer is required")
	}
	if len(trust.ClientIDs) == 0 {
		return nil, errors.New("opkssh: trust.ClientIDs must not be empty")
	}
	return &Verifier{trust: trust}, nil
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
		p, err := oidc.NewProvider(ctx, v.trust.Issuer)
		if err != nil {
			return nil, fmt.Errorf("opkssh: discover issuer %q: %w", v.trust.Issuer, err)
		}
		v.provider.Store(p)
		return p, nil
	})
	if err != nil {
		return nil, err
	}
	return res.(*oidc.Provider), nil
}

// Verify validates the PK Token's OP segment against the configured issuer.
//
// TODO(ENG-2689): also validate the CIC commitment binding the token to
// the presented SSH key, and the cert's ValidAfter/ValidBefore window.
// Both gate production wiring.
func (v *Verifier) Verify(ctx context.Context, key ssh.PublicKey) (*Identity, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert {
		return nil, ErrNotOPKSSHKey
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
		if slices.Contains(v.trust.ClientIDs, a) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("opkssh: audience %v not in allowed client IDs", idToken.Audience)
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("opkssh: decode claims: %w", err)
	}
	return &Identity{
		Issuer:  idToken.Issuer,
		Subject: idToken.Subject,
		Email:   claims.Email,
	}, nil
}

// extractOPJWSFromCompact parses an opkssh compact PK Token and reassembles
// the OP (OIDC) segment as a standard RFC-7515 compact JWS.
//
// Compact format: base64url(payload) ":" base64url(protected1) ":" base64url(sig1)
// [":" base64url(protected2) ":" base64url(sig2) ...] ["." fresh_id_token].
// This draft uses only the first (protected, sig) pair (the OP segment) and
// ignores any trailing CIC / COS segments and the optional fresh_id_token
// suffix.
func extractOPJWSFromCompact(compact string) (string, error) {
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
