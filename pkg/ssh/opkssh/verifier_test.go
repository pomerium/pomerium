// Copyright (c) 2024 Pomerium, Inc.
// SPDX-License-Identifier: Apache-2.0

package opkssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	testClientID = "pomerium-opkssh-client"
	testSubject  = "user-abc-123"
	testEmail    = "alice@example.test"
)

// buildCert returns a signed ed25519 user SSH certificate. extensions may
// be nil. certType defaults to UserCert when zero.
func buildCert(t *testing.T, extensions map[string]string, certType uint32) *ssh.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	if certType == 0 {
		certType = ssh.UserCert
	}
	cert := &ssh.Certificate{
		Key:         sshPub,
		CertType:    certType,
		ValidBefore: uint64(time.Now().Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{Extensions: extensions},
	}
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	require.NoError(t, err)
	require.NoError(t, cert.SignCert(rand.Reader, caSigner))
	return cert
}

func TestNewDraftVerifierWithoutCICBinding_rejectsEmptyTrust(t *testing.T) {
	_, err := NewDraftVerifierWithoutCICBinding(Trust{ClientIDs: []string{"x"}})
	require.Error(t, err)
	_, err = NewDraftVerifierWithoutCICBinding(Trust{Issuer: "https://example.test"})
	require.Error(t, err)
}

func TestVerifier_Verify_happyPath(t *testing.T) {
	idp := startMockOIDC(t)
	opJWS := idp.mintIDToken(t, testClientID, testSubject, testEmail)
	cert := buildCert(t, map[string]string{"openpubkey-pkt": compactFromSingleOPJWS(t, opJWS)}, ssh.UserCert)

	v, err := NewDraftVerifierWithoutCICBinding(Trust{Issuer: idp.issuer(), ClientIDs: []string{testClientID}})
	require.NoError(t, err)

	id, err := v.Verify(context.Background(), cert)
	require.NoError(t, err)
	require.NotNil(t, id)
	assert.Equal(t, idp.issuer(), id.Issuer)
	assert.Equal(t, testSubject, id.Subject)
	assert.Equal(t, testEmail, id.Email)
}

func TestVerifier_Verify_negativePaths(t *testing.T) {
	idp := startMockOIDC(t)
	otherIDP := startMockOIDC(t)

	plainPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	plain, err := ssh.NewPublicKey(plainPub)
	require.NoError(t, err)

	validCompact := compactFromSingleOPJWS(t, idp.mintIDToken(t, testClientID, testSubject, testEmail))

	cases := []struct {
		name    string
		key     ssh.PublicKey
		trust   Trust
		wantIs  error  // errors.Is target, or nil for "any error"
		wantSub string // substring to find in err.Error() when wantIs is nil
	}{
		{
			name:   "plain ed25519 is not an opkssh key",
			key:    plain,
			trust:  Trust{Issuer: idp.issuer(), ClientIDs: []string{testClientID}},
			wantIs: ErrNotOPKSSHKey,
		},
		{
			name:   "user cert without opkssh extension",
			key:    buildCert(t, map[string]string{"permit-pty": ""}, ssh.UserCert),
			trust:  Trust{Issuer: idp.issuer(), ClientIDs: []string{testClientID}},
			wantIs: ErrNotOPKSSHKey,
		},
		{
			name:   "host cert with opkssh extension",
			key:    buildCert(t, map[string]string{"openpubkey-pkt": "payload:protected:sig"}, ssh.HostCert),
			trust:  Trust{Issuer: idp.issuer(), ClientIDs: []string{testClientID}},
			wantIs: ErrNotOPKSSHKey,
		},
		{
			name:   "malformed PK Token extension",
			key:    buildCert(t, map[string]string{"openpubkey-pkt": "not:enough"}, ssh.UserCert),
			trust:  Trust{Issuer: "https://example.test", ClientIDs: []string{testClientID}},
			wantIs: ErrInvalidPKToken,
		},
		{
			name:    "audience not in allow-list",
			key:     buildCert(t, map[string]string{"openpubkey-pkt": compactFromSingleOPJWS(t, idp.mintIDToken(t, "other-app", testSubject, testEmail))}, ssh.UserCert),
			trust:   Trust{Issuer: idp.issuer(), ClientIDs: []string{testClientID}},
			wantSub: "audience",
		},
		{
			name:    "issuer mismatch (token signed by different IdP)",
			key:     buildCert(t, map[string]string{"openpubkey-pkt": validCompact}, ssh.UserCert),
			trust:   Trust{Issuer: otherIDP.issuer(), ClientIDs: []string{testClientID}},
			wantSub: "verify OP token",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewDraftVerifierWithoutCICBinding(tc.trust)
			require.NoError(t, err)
			_, err = v.Verify(context.Background(), tc.key)
			require.Error(t, err)
			if tc.wantIs != nil {
				assert.True(t, errors.Is(err, tc.wantIs), "want errors.Is(%v), got %v", tc.wantIs, err)
			}
			if tc.wantSub != "" {
				assert.Contains(t, err.Error(), tc.wantSub)
				// Negative-space guard: verification failures must NOT
				// alias the fall-through sentinels; otherwise the hook
				// would silently accept them as "not opkssh".
				assert.False(t, errors.Is(err, ErrNotOPKSSHKey))
				assert.False(t, errors.Is(err, ErrInvalidPKToken))
			}
		})
	}
}
