package storage

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type benchmarkCountingQuerier struct {
	Querier
	queryCount int
}

func (q *benchmarkCountingQuerier) Query(
	ctx context.Context,
	in *databroker.QueryRequest,
	opts ...grpc.CallOption,
) (*databroker.QueryResponse, error) {
	q.queryCount++
	return q.Querier.Query(ctx, in, opts...)
}

func newBenchSession() *session.Session {
	now := time.Now()
	return &session.Session{
		Version:    "1",
		Id:         "1a5e57ce-6bd0-4e00-9a1a-3f3c1b1b5b8f",
		UserId:     "IdP-User-ID/1a5e57ce-6bd0-4e00-9a1a-3f3c1b1b5b8f",
		IssuedAt:   timestamppb.New(now),
		ExpiresAt:  timestamppb.New(now.Add(time.Hour)),
		AccessedAt: timestamppb.New(now),
		IdToken: &session.IDToken{
			Issuer:    "https://accounts.example.com",
			Subject:   "1a5e57ce-6bd0-4e00-9a1a-3f3c1b1b5b8f",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
			IssuedAt:  timestamppb.New(now),
			Raw:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
		},
		OauthToken: &session.OAuthToken{
			AccessToken:  "ya29.a0ARrdaM-example-access-token-value",
			TokenType:    "Bearer",
			ExpiresAt:    timestamppb.New(now.Add(time.Hour)),
			RefreshToken: "1//0g-example-refresh-token-value",
		},
		Claims: map[string]*structpb.ListValue{
			"email":          {Values: []*structpb.Value{structpb.NewStringValue("user@example.com")}},
			"email_verified": {Values: []*structpb.Value{structpb.NewBoolValue(true)}},
			"groups": {Values: []*structpb.Value{
				structpb.NewStringValue("engineering"),
				structpb.NewStringValue("everyone"),
				structpb.NewStringValue("admins"),
			}},
			"name": {Values: []*structpb.Value{structpb.NewStringValue("Example User")}},
		},
		Audience: []string{"pomerium-proxy", "pomerium-authenticate"},
		IdpId:    "google",
	}
}

func BenchmarkCachingQuerierHit(b *testing.B) {
	ctx := b.Context()
	sess := newBenchSession()
	inner := &benchmarkCountingQuerier{Querier: NewStaticQuerier(sess)}
	cache := NewGlobalCache(time.Minute)
	q := NewCachingQuerier(inner, cache)

	req := &databroker.QueryRequest{
		Type:  "type.googleapis.com/session.Session",
		Limit: 1,
	}
	req.SetFilterByIDOrIndex(sess.Id)

	res, err := q.Query(ctx, req)
	if err != nil {
		b.Fatal(err)
	}
	if len(res.GetRecords()) != 1 || res.GetRecords()[0].GetId() != sess.GetId() {
		b.Fatal("unexpected cached query response")
	}
	if inner.queryCount != 1 {
		b.Fatal("expected one query to warm the cache")
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := q.Query(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
	if inner.queryCount != 1 {
		b.Fatalf("cache miss during benchmark: underlying query count = %d", inner.queryCount)
	}
}

func BenchmarkCachingQuerierCacheKey(b *testing.B) {
	sess := newBenchSession()
	inner := NewStaticQuerier(sess)
	cache := NewGlobalCache(time.Minute)
	q := NewCachingQuerier(inner, cache).(*cachingQuerier)

	req := &databroker.QueryRequest{
		Type:  "type.googleapis.com/session.Session",
		Limit: 1,
	}
	req.SetFilterByIDOrIndex(sess.Id)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := q.getCacheKey(req); err != nil {
			b.Fatal(err)
		}
	}
}
