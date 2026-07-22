package evaluator

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/storage"
)

// BenchmarkEvaluate measures a full Evaluator.Evaluate call - policy rules
// plus the headers evaluator, including JWT signing - for one request against
// one policy. Evaluate's cost does not scale with the total policy count
// (per-policy Rego is compiled in New, outside the timed loop), so there is
// no policy-count axis; this is the composite regression guard for the
// per-request authorize path.
func BenchmarkEvaluate(b *testing.B) {
	prevLevel := log.GetLevel()
	log.SetLevel(zerolog.InfoLevel)
	defer log.SetLevel(prevLevel)

	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(b, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(b, err)

	policies := make([]*config.Policy, 100)
	for i := range policies {
		policies[i] = &config.Policy{
			From:         fmt.Sprintf("https://from-%d.example.com", i),
			To:           singleToURL(fmt.Sprintf("https://to-%d.example.com", i)),
			AllowedUsers: []string{"u1@example.com"},
			SetRequestHeaders: map[string]string{
				"Authorization": "Bearer ${pomerium.jwt}",
			},
		}
	}
	mid := len(policies) / 2
	policy := policies[mid]

	ctx := b.Context()
	ctx = storage.WithQuerier(ctx, storage.NewStaticQuerier([]proto.Message{
		&session.Session{Id: "s1", UserId: "u1"},
		&user.User{Id: "u1", Email: "u1@example.com"},
	}...))

	st := store.New()
	st.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user"))

	e, err := New(ctx, st, nil,
		WithPolicies(policies),
		WithSigningKey(encodedSigningKey),
		WithAuthenticateURL("https://authenticate.example.com"),
	)
	require.NoError(b, err)

	host := fmt.Sprintf("from-%d.example.com", mid)
	req := &Request{
		Policy: policy,
		HTTP: RequestHTTP{
			Method:   http.MethodGet,
			Host:     host,
			Hostname: host,
			Path:     "/",
			URL:      "https://" + host + "/",
		},
		Session: RequestSession{ID: "s1", UserID: "u1"},
	}
	res, err := e.Evaluate(ctx, req)
	require.NoError(b, err)
	require.True(b, res.Allow.Value)
	require.NotEmpty(b, res.Headers.Get("Authorization"))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		res, err = e.Evaluate(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}
