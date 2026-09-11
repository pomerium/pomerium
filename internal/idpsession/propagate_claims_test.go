package idpsession

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	dtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

// ApplyToSession merges the IdP's claims into the dependent session rather than
// assigning them, so a claim the reconciler did not author survives propagation
// — TestApplySessionClaims pins that at the applier. This is the same invariant
// end to end: the record handed to Patch is synthesized from an empty session
// and "claims" is in the session field mask, so the merge has to happen against
// what the store already holds, not against the synthesized blank.
func TestPropagatePreservesSessionOwnClaims(t *testing.T) {
	now := time.Now()
	zerolog.SetGlobalLevel(zerolog.Disabled)
	client := dtestutil.NewTestDatabroker(t)

	authenticator := &mockAuthenticator{
		refreshResult: &oauth2.Token{
			AccessToken:  "access-token",
			TokenType:    "Bearer",
			RefreshToken: "refresh-token",
			Expiry:       now.Add(time.Hour),
		},
	}
	authGetter := func(_ context.Context, _ string) (identity.Authenticator, error) {
		return authenticator, nil
	}

	mgr := NewIdentityManagerV2(
		databroker.NewStaticClientGetter(client),
		authGetter,
		WithReconcileInterval(time.Millisecond*50),
	)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go mgr.Run(ctx)

	claims, err := structpb.NewStruct(map[string]any{
		"email":  "bob@example.com",
		"groups": []any{"engineering"},
	})
	require.NoError(t, err)

	idpSess := &idpsession.IDPSession{
		Id:         "bob",
		RawIdToken: "raw-id-token",
		IdToken: &idpsession.IDToken{
			Issuer:    "https://idp.example.com",
			Subject:   "bob",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
			IssuedAt:  timestamppb.New(now),
		},
		OauthToken: &idpsession.OAuthToken{
			AccessToken:  "access-token",
			TokenType:    "Bearer",
			ExpiresAt:    timestamppb.New(now.Add(time.Hour)),
			RefreshToken: "refresh-token",
		},
		Claims: claims,
	}

	sess := &session.Session{
		Id:        "session-1",
		UserId:    "bob",
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}
	sess.AddClaims(identity.FlattenedClaims{
		// claims the session owns rather than inherits from the IdP
		"device_id":    {"device-1"},
		"login_method": {"webauthn"},
		// a claim the session and the IdP both have: the IdP wins
		"email": {"stale@example.com"},
	})

	records := append(
		[]*databroker.Record{databroker.NewRecord(idpSess)},
		newSessionWithBinding(sess, idpSess.GetId())...,
	)

	_, err = client.Put(t.Context(), &databroker.PutRequest{Records: records})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		got := &session.Session{Id: sess.GetId()}
		if !assert.NoError(collect, databroker.Get(t.Context(), client, got)) {
			return
		}

		// the IDPSession has been propagated onto the bound session
		assert.Equal(collect, idpSess.GetOauthToken().GetAccessToken(), got.GetOauthToken().GetAccessToken())
		assert.Equal(collect, idpSess.GetIdToken().GetIssuer(), got.GetIdToken().GetIssuer())

		// and the claims the session owns are still there
		assert.Equal(collect, "device-1", firstClaim(got, "device_id"))
		assert.Equal(collect, "webauthn", firstClaim(got, "login_method"))

		// while a claim the IdP also asserts is refreshed from the IdP
		assert.Equal(collect, "bob@example.com", firstClaim(got, "email"))
	}, 5*time.Second, 10*time.Millisecond)
}

// firstClaim returns the first value of a claim, or "" when the claim is absent
// — indexing directly would panic inside the EventuallyWithT goroutine and take
// the whole test binary down instead of failing the assertion.
func firstClaim(s *session.Session, key string) string {
	values := s.GetClaims()[key].GetValues()
	if len(values) == 0 {
		return ""
	}
	return values[0].GetStringValue()
}
