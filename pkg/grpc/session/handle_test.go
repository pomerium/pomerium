package session_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestHandle(t *testing.T) {
	t.Parallel()

	var h session.Handle
	assert.NoError(t, json.Unmarshal(json.RawMessage(`{
		"jti": "ID",
		"sub": "USER_ID",
		"idp_id": "IDENTITY_PROVIDER_ID",
		"databroker_server_version": 1001,
		"databroker_record_version": 10001,
		"iss": "ISSUER",
		"aud": ["AUDIENCE1","AUDIENCE2"],
		"exp": 1500000000,
		"nbf": 1600000000,
		"iat": 1700000000
	}`), &h))
	assert.Empty(t, cmp.Diff(&session.Handle{
		Id:                      "ID",
		UserId:                  "USER_ID",
		IdentityProviderId:      "IDENTITY_PROVIDER_ID",
		DatabrokerServerVersion: proto.Uint64(1001),
		DatabrokerRecordVersion: proto.Uint64(10001),
		Iss:                     proto.String("ISSUER"),
		Aud:                     []string{"AUDIENCE1", "AUDIENCE2"},
		Exp:                     timestamppb.New(time.Unix(1500000000, 0)),
		Nbf:                     timestamppb.New(time.Unix(1600000000, 0)),
		Iat:                     timestamppb.New(time.Unix(1700000000, 0)),
	}, &h, protocmp.Transform()))

	assert.NoError(t, json.Unmarshal(json.RawMessage(`{
		"sub": "USER_ID1",
		"oid": "USER_ID2"
	}`), &h))
	assert.Equal(t, "USER_ID2", h.UserId)

	bs, err := json.Marshal(&h)
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"jti": "ID",
		"sub": "USER_ID2",
		"idp_id": "IDENTITY_PROVIDER_ID",
		"databroker_server_version": 1001,
		"databroker_record_version": 10001,
		"iss": "ISSUER",
		"aud": ["AUDIENCE1","AUDIENCE2"],
		"exp": 1500000000,
		"nbf": 1600000000,
		"iat": 1700000000
	}`, string(bs))
}

func TestHandle_WithNewIssuer(t *testing.T) {
	t.Parallel()

	t.Run("preserves TTL", func(t *testing.T) {
		t.Parallel()
		baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		h := &session.Handle{
			Id:                 "test-id",
			UserId:             "user-1",
			IdentityProviderId: "idp-1",
			Iss:                proto.String("original-issuer"),
			Aud:                []string{"original-aud"},
			Iat:                timestamppb.New(baseTime),
			Exp:                timestamppb.New(baseTime.Add(time.Hour)),
		}

		result := h.WithNewIssuer("new-issuer", []string{"new-aud"})

		assert.Equal(t, "new-issuer", *result.Iss)
		assert.Equal(t, []string{"new-aud"}, result.Aud)
		assert.NotNil(t, result.Exp)
		ttl := result.Exp.AsTime().Sub(result.Iat.AsTime())
		assert.Equal(t, time.Hour, ttl)
		assert.WithinDuration(t, time.Now(), result.Iat.AsTime(), 5*time.Second)
	})

	t.Run("clears Nbf", func(t *testing.T) {
		t.Parallel()
		baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		h := &session.Handle{
			Id:  "test-id",
			Iat: timestamppb.New(baseTime),
			Exp: timestamppb.New(baseTime.Add(time.Hour)),
			Nbf: timestamppb.New(baseTime),
		}

		result := h.WithNewIssuer("issuer", []string{"aud"})

		assert.Nil(t, result.Nbf)
	})

	t.Run("nil Exp", func(t *testing.T) {
		t.Parallel()
		h := &session.Handle{
			Id:  "test-id",
			Iat: timestamppb.Now(),
		}

		result := h.WithNewIssuer("issuer", []string{"aud"})

		assert.Nil(t, result.Exp)
		assert.NotNil(t, result.Iat)
	})

	t.Run("nil Iat", func(t *testing.T) {
		t.Parallel()
		h := &session.Handle{
			Id:  "test-id",
			Exp: timestamppb.New(time.Now().Add(-time.Hour)),
		}

		result := h.WithNewIssuer("issuer", []string{"aud"})

		assert.Nil(t, result.Exp)
	})

	t.Run("negative duration clears Exp", func(t *testing.T) {
		t.Parallel()
		baseTime := time.Now()
		h := &session.Handle{
			Id:  "test-id",
			Iat: timestamppb.New(baseTime),
			Exp: timestamppb.New(baseTime.Add(-time.Hour)),
		}

		result := h.WithNewIssuer("issuer", []string{"aud"})

		assert.Nil(t, result.Exp)
	})

	t.Run("both nil", func(t *testing.T) {
		t.Parallel()
		h := &session.Handle{Id: "test-id"}

		result := h.WithNewIssuer("issuer", []string{"aud"})

		assert.Nil(t, result.Exp)
		assert.Nil(t, result.Nbf)
		assert.NotNil(t, result.Iat)
	})

	t.Run("does not mutate original", func(t *testing.T) {
		t.Parallel()
		baseTime := time.Now()
		h := &session.Handle{
			Id:  "test-id",
			Iss: proto.String("original"),
			Aud: []string{"original-aud"},
			Iat: timestamppb.New(baseTime),
			Exp: timestamppb.New(baseTime.Add(time.Hour)),
			Nbf: timestamppb.New(baseTime),
		}

		_ = h.WithNewIssuer("new-issuer", []string{"new-aud"})

		assert.Equal(t, "original", *h.Iss)
		assert.Equal(t, []string{"original-aud"}, h.Aud)
		assert.NotNil(t, h.Exp)
		assert.NotNil(t, h.Nbf)
	})

	// Regression test for the actual bug Joe hit: handle created from an
	// IdP token hours ago, then reissued now. Before the fix, the resulting
	// JWT had exp far in the past (exp < iat).
	t.Run("stale handle reissue produces valid exp", func(t *testing.T) {
		t.Parallel()
		// Simulate: IdP issued a token 21 hours ago with a 1-hour TTL.
		idpIssuedAt := time.Now().Add(-21 * time.Hour)
		idpExp := idpIssuedAt.Add(time.Hour) // expired 20 hours ago

		h := &session.Handle{
			Id:                 "session-abc",
			UserId:             "101230826209618995874",
			IdentityProviderId: "zShKJzyKdzyGGZraMmAVopVLpKsUsYreY9EjJYwpuDR",
			Iss:                proto.String("authn.k8s.bdd.io"),
			Aud:                []string{"authn.k8s.bdd.io"},
			Iat:                timestamppb.New(idpIssuedAt),
			Exp:                timestamppb.New(idpExp),
			Nbf:                timestamppb.New(idpIssuedAt),
		}

		// This is what Stateful.SignIn does: reissue with new audiences.
		result := h.WithNewIssuer("authn.k8s.bdd.io", []string{
			"authn.k8s.bdd.io", "127.0.0.1:36231", "buildbarn-reapi.k8s.bdd.io",
		})

		// The critical assertion: exp MUST be in the future, not 20 hours ago.
		assert.True(t, result.Exp.AsTime().After(time.Now()),
			"exp must be in the future, got %v", result.Exp.AsTime())
		assert.True(t, result.Iat.AsTime().Before(result.Exp.AsTime()),
			"iat must be before exp: iat=%v exp=%v", result.Iat.AsTime(), result.Exp.AsTime())

		// TTL should be preserved at ~1 hour.
		ttl := result.Exp.AsTime().Sub(result.Iat.AsTime())
		assert.Equal(t, time.Hour, ttl)

		// Nbf should be cleared.
		assert.Nil(t, result.Nbf)
	})

	t.Run("updates Iss and Aud", func(t *testing.T) {
		t.Parallel()
		h := &session.Handle{
			Id:                 "test-id",
			UserId:             "user-1",
			IdentityProviderId: "idp-1",
			Iss:                proto.String("old-issuer"),
			Aud:                []string{"old-aud"},
			Iat:                timestamppb.Now(),
		}

		result := h.WithNewIssuer("new-issuer", []string{"aud1", "aud2"})

		assert.Equal(t, "new-issuer", *result.Iss)
		assert.Equal(t, []string{"aud1", "aud2"}, result.Aud)
		assert.Equal(t, "test-id", result.Id)
		assert.Equal(t, "user-1", result.UserId)
		assert.Equal(t, "idp-1", result.IdentityProviderId)
	})
}
