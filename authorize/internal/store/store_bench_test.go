package store

import (
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

// BenchmarkStoreGetDataBrokerRecord measures the get_databroker_record rego
// builtin end to end: the querier round-trip, toMap's JSON marshal/unmarshal,
// and ast.InterfaceToValue. It resolves the session and user records used by
// a typical authenticated policy evaluation.
func BenchmarkStoreGetDataBrokerRecord(b *testing.B) {
	s := New()

	sessionType := grpcutil.GetTypeURL(new(session.Session))
	userType := grpcutil.GetTypeURL(new(user.User))

	script := fmt.Sprintf(`package pomerium.policy

session := get_databroker_record(%q, "s1")
user := get_databroker_record(%q, "u1")
`, sessionType, userType)

	r := rego.New(
		rego.Store(s),
		rego.Module("pomerium.policy", script),
		rego.Query("result = data.pomerium.policy"),
		s.GetDataBrokerRecordOption(),
	)
	pq, err := r.PrepareForEval(b.Context())
	require.NoError(b, err)

	sess := &session.Session{
		Id:       "s1",
		UserId:   "u1",
		IdpId:    "idp1",
		Audience: []string{"https://from.example.com"},
	}
	u := &user.User{
		Id:    "u1",
		Name:  "Jane Doe",
		Email: "jane@example.com",
	}
	ctx := storage.WithQuerier(b.Context(), storage.NewStaticQuerier(sess, u))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rs, err := pq.Eval(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if len(rs) == 0 {
			b.Fatal("expected a result")
		}
	}
}
