// Copyright (c) 2024 Pomerium, Inc.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"context"
	"errors"

	gossh "golang.org/x/crypto/ssh"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/ssh/opkssh"
)

// tryOPKSSH parses the presented public key and, if it is an SSH
// certificate, runs it through the opkssh verifier. See ENG-2689.
//
// Return shape:
//
//   - (_, false, nil): key is not an opkssh cert; caller continues with
//     the existing auth flow.
//   - (resp, true, nil): verification failed on an opkssh-shaped cert;
//     caller returns resp to tell the client "not this key, try another".
//   - (_, true, err): internal error (e.g. OIDC issuer unreachable);
//     caller surfaces err.
//
// DRAFT: the success case currently returns (_, false, nil) — i.e. it
// falls through to the existing device-code flow. The follow-up commit
// will mint a Session + SessionBinding here and return (allow, true, nil).
// See the TODO inside.
func tryOPKSSH(
	ctx context.Context,
	v OPKSSHVerifier,
	req *extensions_ssh.PublicKeyMethodRequest,
) (PublicKeyAuthMethodResponse, bool, error) {
	// opkssh metadata only travels inside SSH certificate extensions, so
	// non-cert keys can never carry it. Skip without invoking the verifier.
	parsed, err := gossh.ParsePublicKey(req.PublicKey)
	if err != nil {
		return PublicKeyAuthMethodResponse{}, false, nil
	}
	if _, isCert := parsed.(*gossh.Certificate); !isCert {
		return PublicKeyAuthMethodResponse{}, false, nil
	}
	id, verr := v.Verify(ctx, parsed)
	if errors.Is(verr, opkssh.ErrNotOPKSSHKey) {
		return PublicKeyAuthMethodResponse{}, false, nil
	}
	if verr != nil {
		// ErrInvalidPKToken gets a distinct message so ops can tell "client
		// sent a garbage PKT" from "signature check failed" at a glance.
		logEvent := log.Ctx(ctx).Warn().Err(verr)
		if errors.Is(verr, opkssh.ErrInvalidPKToken) {
			logEvent.Msg("opkssh rejected: malformed PK Token extension")
		} else {
			logEvent.Msg("opkssh verification failed")
		}
		return PublicKeyAuthMethodResponse{
			RequireAdditionalMethods: []string{MethodPublicKey},
		}, true, nil
	}
	// DRAFT ONLY: opkssh verification succeeded, but we intentionally
	// return handled=false and log at Debug so the existing session-
	// binding flow runs. The follow-up commit will factor the
	// Session+SessionBinding builder out of internal/authenticateflow/
	// stateful.go:237 (AuthenticatePendingSession) and call it from here,
	// at which point this branch returns a publicKeyAllowResponse and
	// skips the keyboard-interactive prompt.
	//
	// TODO(ENG-2689): replace this branch with the real success path
	// before flipping WithOPKSSHVerifier in production wiring. The
	// covering test is TestTryOPKSSH_draftSuccessFallsThrough; delete it
	// in the same commit that implements session minting.
	log.Ctx(ctx).Debug().
		Str("issuer", id.Issuer).
		Str("subject", id.Subject).
		Str("email", id.Email).
		Msg("opkssh verified; draft falls through to device-code flow")
	return PublicKeyAuthMethodResponse{}, false, nil
}
