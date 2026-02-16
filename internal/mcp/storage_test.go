package mcp_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/mcp"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/internal/testutil"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestStorage(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute*5)

	list := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() {
		list.Close()
	})

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	grpcServer := grpc.NewServer()
	databroker_grpc.RegisterDataBrokerServiceServer(grpcServer, srv)

	go func() {
		if err := grpcServer.Serve(list); err != nil {
			t.Errorf("failed to serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
	})

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return list.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	client := databroker_grpc.NewDataBrokerServiceClient(conn)
	storage := mcp.NewStorage(client)

	t.Run("client registration", func(t *testing.T) {
		t.Parallel()

		id, err := storage.RegisterClient(ctx, &rfc7591v1.ClientRegistration{})
		require.NoError(t, err)
		require.NotEmpty(t, id)

		_, err = storage.GetClient(ctx, id)
		require.NoError(t, err)
	})

	t.Run("authorization request", func(t *testing.T) {
		t.Parallel()

		id, err := storage.CreateAuthorizationRequest(ctx, &oauth21proto.AuthorizationRequest{})
		require.NoError(t, err)

		_, err = storage.GetAuthorizationRequest(ctx, id)
		require.NoError(t, err)
	})

	t.Run("upstream oauth2 token", func(t *testing.T) {
		t.Parallel()

		want := &oauth21proto.TokenResponse{
			AccessToken:  "access-token",
			TokenType:    "token-type",
			ExpiresIn:    proto.Int64(3600),
			RefreshToken: proto.String("refresh-token"),
			Scope:        proto.String("scope"),
		}
		err := storage.StoreUpstreamOAuth2Token(ctx, "host", "user-id", want)
		require.NoError(t, err)

		got, err := storage.GetUpstreamOAuth2Token(ctx, "host", "user-id")
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(want, got, protocmp.Transform()))

		_, err = storage.GetUpstreamOAuth2Token(ctx, "non-existent-host", "user-id")
		assert.Equal(t, codes.NotFound, status.Code(err))

		_, err = storage.GetUpstreamOAuth2Token(ctx, "host", "non-existent-user-id")
		assert.Equal(t, codes.NotFound, status.Code(err))

		err = storage.DeleteUpstreamOAuth2Token(ctx, "host", "user-id")
		require.NoError(t, err)

		_, err = storage.GetUpstreamOAuth2Token(ctx, "host", "user-id")
		assert.Equal(t, codes.NotFound, status.Code(err))

		err = storage.DeleteUpstreamOAuth2Token(ctx, "non-existent-host", "user-id")
		assert.NoError(t, err)
	})

	t.Run("upstream mcp token", func(t *testing.T) {
		t.Parallel()

		token := &oauth21proto.UpstreamMCPToken{
			UserId:                    "user-123",
			RouteId:                   "route-456",
			UpstreamServer:            "https://mcp.example.com",
			AccessToken:               "access-token-xyz",
			RefreshToken:              "refresh-token-abc",
			TokenType:                 "Bearer",
			Scopes:                    []string{"mcp:read", "mcp:write"},
			Audience:                  "https://resource.example.com",
			AuthorizationServerIssuer: "https://auth.example.com",
			TokenEndpoint:             "https://auth.example.com/token",
		}

		// Store token first so subsequent tests can use it
		err := storage.PutUpstreamMCPToken(t.Context(), token)
		require.NoError(t, err)

		t.Run("store and retrieve", func(t *testing.T) {
			got, err := storage.GetUpstreamMCPToken(t.Context(), "user-123", "route-456", "https://mcp.example.com")
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(token, got, protocmp.Transform()))
		})

		t.Run("get not found", func(t *testing.T) {
			t.Parallel()

			tests := []struct {
				name           string
				userID         string
				routeID        string
				upstreamServer string
			}{
				{"wrong user", "non-existent-user", "route-456", "https://mcp.example.com"},
				{"wrong route", "user-123", "non-existent-route", "https://mcp.example.com"},
				{"wrong upstream server", "user-123", "route-456", "https://non-existent.example.com"},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					t.Parallel()

					_, err := storage.GetUpstreamMCPToken(t.Context(), tt.userID, tt.routeID, tt.upstreamServer)
					assert.Equal(t, codes.NotFound, status.Code(err))
				})
			}
		})

		t.Run("update overwrites", func(t *testing.T) {
			updated := proto.Clone(token).(*oauth21proto.UpstreamMCPToken)
			updated.AccessToken = "refreshed-access-token"

			err := storage.PutUpstreamMCPToken(t.Context(), updated)
			require.NoError(t, err)

			got, err := storage.GetUpstreamMCPToken(t.Context(), "user-123", "route-456", "https://mcp.example.com")
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(updated, got, protocmp.Transform()))
		})

		t.Run("delete", func(t *testing.T) {
			// Store a token specifically for deletion
			toDelete := proto.Clone(token).(*oauth21proto.UpstreamMCPToken)
			toDelete.UserId = "del-user"
			toDelete.RouteId = "del-route"
			toDelete.UpstreamServer = "https://del.example.com"

			err := storage.PutUpstreamMCPToken(t.Context(), toDelete)
			require.NoError(t, err)

			err = storage.DeleteUpstreamMCPToken(t.Context(), "del-user", "del-route", "https://del.example.com")
			require.NoError(t, err)

			_, err = storage.GetUpstreamMCPToken(t.Context(), "del-user", "del-route", "https://del.example.com")
			assert.Equal(t, codes.NotFound, status.Code(err))
		})

		t.Run("delete non-existent is idempotent", func(t *testing.T) {
			t.Parallel()

			err := storage.DeleteUpstreamMCPToken(t.Context(), "no-user", "no-route", "https://no.example.com")
			assert.NoError(t, err)
		})

		t.Run("rejects empty key components", func(t *testing.T) {
			t.Parallel()

			tests := []struct {
				name           string
				userID         string
				routeID        string
				upstreamServer string
			}{
				{"empty user_id", "", "route", "https://example.com"},
				{"empty route_id", "user", "", "https://example.com"},
				{"empty upstream_server", "user", "route", ""},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					t.Parallel()

					err := storage.PutUpstreamMCPToken(t.Context(), &oauth21proto.UpstreamMCPToken{
						UserId:         tt.userID,
						RouteId:        tt.routeID,
						UpstreamServer: tt.upstreamServer,
						AccessToken:    "tok",
					})
					assert.Error(t, err)
				})
			}
		})
	})

	t.Run("mcp refresh token", func(t *testing.T) {
		t.Parallel()

		want := &oauth21proto.MCPRefreshToken{
			Id:                   "test-refresh-token-id",
			UserId:               "test-user-id",
			ClientId:             "test-client-id",
			IdpId:                "test-idp-id",
			UpstreamRefreshToken: "upstream-refresh-token",
			Scopes:               []string{"openid", "profile"},
		}

		// Store refresh token
		err := storage.PutMCPRefreshToken(ctx, want)
		require.NoError(t, err)

		// Retrieve refresh token
		got, err := storage.GetMCPRefreshToken(ctx, want.Id)
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(want, got, protocmp.Transform()))

		// Non-existent refresh token
		_, err = storage.GetMCPRefreshToken(ctx, "non-existent-id")
		assert.Equal(t, codes.NotFound, status.Code(err))

		// Update refresh token (mark as revoked)
		want.Revoked = true
		err = storage.PutMCPRefreshToken(ctx, want)
		require.NoError(t, err)

		got, err = storage.GetMCPRefreshToken(ctx, want.Id)
		require.NoError(t, err)
		assert.True(t, got.Revoked)

		// Delete refresh token
		err = storage.DeleteMCPRefreshToken(ctx, want.Id)
		require.NoError(t, err)

		_, err = storage.GetMCPRefreshToken(ctx, want.Id)
		assert.Equal(t, codes.NotFound, status.Code(err))

		// Delete non-existent refresh token should not error
		err = storage.DeleteMCPRefreshToken(ctx, "non-existent-id")
		assert.NoError(t, err)
	})

	t.Run("upstream oauth client", func(t *testing.T) {
		t.Parallel()

		want := &oauth21proto.UpstreamOAuthClient{
			Issuer:               "https://auth.example.com",
			DownstreamHost:       "app.localhost.pomerium.io",
			ClientId:             "dcr-client-id",
			ClientSecret:         "dcr-client-secret",
			RedirectUri:          "https://app.localhost.pomerium.io/.pomerium/mcp/upstream/callback",
			RegistrationEndpoint: "https://auth.example.com/register",
			CreatedAt:            timestamppb.Now(),
		}

		err := storage.PutUpstreamOAuthClient(ctx, want)
		require.NoError(t, err)

		got, err := storage.GetUpstreamOAuthClient(ctx, want.Issuer, want.DownstreamHost)
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(want, got, protocmp.Transform()))

		// Different issuer → not found
		_, err = storage.GetUpstreamOAuthClient(ctx, "https://other-issuer.com", want.DownstreamHost)
		assert.Equal(t, codes.NotFound, status.Code(err))

		// Different downstream host → not found
		_, err = storage.GetUpstreamOAuthClient(ctx, want.Issuer, "other.localhost.pomerium.io")
		assert.Equal(t, codes.NotFound, status.Code(err))

		// Update overwrites
		updated := proto.Clone(want).(*oauth21proto.UpstreamOAuthClient)
		updated.ClientId = "new-client-id"
		updated.ClientSecret = "new-client-secret"
		err = storage.PutUpstreamOAuthClient(ctx, updated)
		require.NoError(t, err)

		got, err = storage.GetUpstreamOAuthClient(ctx, want.Issuer, want.DownstreamHost)
		require.NoError(t, err)
		assert.Equal(t, "new-client-id", got.ClientId)
		assert.Equal(t, "new-client-secret", got.ClientSecret)

		// Rejects empty issuer
		err = storage.PutUpstreamOAuthClient(ctx, &oauth21proto.UpstreamOAuthClient{
			Issuer:         "",
			DownstreamHost: "host",
			ClientId:       "id",
		})
		assert.Error(t, err)

		// Rejects empty downstream host
		err = storage.PutUpstreamOAuthClient(ctx, &oauth21proto.UpstreamOAuthClient{
			Issuer:         "https://issuer.com",
			DownstreamHost: "",
			ClientId:       "id",
		})
		assert.Error(t, err)
	})

	t.Run("pending upstream auth", func(t *testing.T) {
		t.Parallel()

		want := &oauth21proto.PendingUpstreamAuth{
			StateId:                   "test-state-abc",
			UserId:                    "user-42",
			RouteId:                   "route-99",
			UpstreamServer:            "https://mcp.upstream.example.com",
			PkceVerifier:              "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			Scopes:                    []string{"mcp:read", "mcp:write"},
			AuthorizationEndpoint:     "https://auth.example.com/authorize",
			TokenEndpoint:             "https://auth.example.com/token",
			AuthorizationServerIssuer: "https://auth.example.com",
			OriginalUrl:               "https://app.example.com/resource",
			RedirectUri:               "https://app.example.com/.pomerium/mcp/upstream/callback",
			ClientId:                  "https://app.example.com/.pomerium/mcp/client-id",
			CreatedAt:                 timestamppb.Now(),
			DownstreamHost:            "app.example.com",
			AuthReqId:                 "auth-req-123",
			PkceChallenge:             "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			ClientSecret:              "optional-dcr-secret",
		}

		err := storage.PutPendingUpstreamAuth(ctx, want)
		require.NoError(t, err)

		t.Run("store and retrieve", func(t *testing.T) {
			got, err := storage.GetPendingUpstreamAuth(ctx, "test-state-abc")
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(want, got, protocmp.Transform()))
		})

		t.Run("get not found", func(t *testing.T) {
			t.Parallel()

			_, err := storage.GetPendingUpstreamAuth(ctx, "non-existent-state")
			assert.Equal(t, codes.NotFound, status.Code(err))
		})

		t.Run("update overwrites", func(t *testing.T) {
			updated := proto.Clone(want).(*oauth21proto.PendingUpstreamAuth)
			updated.AuthReqId = "updated-auth-req-456"

			err := storage.PutPendingUpstreamAuth(ctx, updated)
			require.NoError(t, err)

			got, err := storage.GetPendingUpstreamAuth(ctx, "test-state-abc")
			require.NoError(t, err)
			assert.Equal(t, "updated-auth-req-456", got.AuthReqId)
		})

		t.Run("delete", func(t *testing.T) {
			toDelete := &oauth21proto.PendingUpstreamAuth{
				StateId:       "del-state",
				UserId:        "u",
				RouteId:       "r",
				PkceVerifier:  "v",
				TokenEndpoint: "t",
				RedirectUri:   "r",
				ClientId:      "c",
			}
			err := storage.PutPendingUpstreamAuth(ctx, toDelete)
			require.NoError(t, err)

			err = storage.DeletePendingUpstreamAuth(ctx, "del-state")
			require.NoError(t, err)

			_, err = storage.GetPendingUpstreamAuth(ctx, "del-state")
			assert.Equal(t, codes.NotFound, status.Code(err))
		})

		t.Run("delete non-existent is idempotent", func(t *testing.T) {
			t.Parallel()

			err := storage.DeletePendingUpstreamAuth(ctx, "never-existed")
			assert.NoError(t, err)
		})

		t.Run("rejects empty state_id", func(t *testing.T) {
			t.Parallel()

			err := storage.PutPendingUpstreamAuth(ctx, &oauth21proto.PendingUpstreamAuth{})
			assert.Error(t, err)
		})

		t.Run("index lookup", func(t *testing.T) {
			indexed := &oauth21proto.PendingUpstreamAuth{
				StateId:        "idx-test-state",
				UserId:         "idx-user",
				RouteId:        "idx-route",
				PkceVerifier:   "idx-verifier",
				TokenEndpoint:  "https://auth.example.com/token",
				RedirectUri:    "https://app.example.com/callback",
				ClientId:       "idx-client",
				DownstreamHost: "idx-host.example.com",
			}
			err := storage.PutPendingUpstreamAuth(ctx, indexed)
			require.NoError(t, err)

			err = storage.PutPendingUpstreamAuthIndex(ctx, "idx-user", "idx-host.example.com", "idx-test-state")
			require.NoError(t, err)

			got, err := storage.GetPendingUpstreamAuthByUserAndHost(ctx, "idx-user", "idx-host.example.com")
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(indexed, got, protocmp.Transform()))
		})

		t.Run("index lookup wrong user", func(t *testing.T) {
			t.Parallel()

			_, err := storage.GetPendingUpstreamAuthByUserAndHost(ctx, "wrong-user", "idx-host.example.com")
			assert.Error(t, err)
		})

		t.Run("index lookup wrong host", func(t *testing.T) {
			t.Parallel()

			_, err := storage.GetPendingUpstreamAuthByUserAndHost(ctx, "idx-user", "wrong-host.example.com")
			assert.Error(t, err)
		})

		t.Run("delete index", func(t *testing.T) {
			delIndexed := &oauth21proto.PendingUpstreamAuth{
				StateId:       "del-idx-state",
				UserId:        "del-idx-user",
				RouteId:       "r",
				PkceVerifier:  "v",
				TokenEndpoint: "t",
				RedirectUri:   "r",
				ClientId:      "c",
			}
			err := storage.PutPendingUpstreamAuth(ctx, delIndexed)
			require.NoError(t, err)

			err = storage.PutPendingUpstreamAuthIndex(ctx, "del-idx-user", "del-idx-host", "del-idx-state")
			require.NoError(t, err)

			err = storage.DeletePendingUpstreamAuthIndex(ctx, "del-idx-user", "del-idx-host")
			require.NoError(t, err)

			// Index lookup should fail
			_, err = storage.GetPendingUpstreamAuthByUserAndHost(ctx, "del-idx-user", "del-idx-host")
			assert.Error(t, err)

			// Primary record should still be accessible
			got, err := storage.GetPendingUpstreamAuth(ctx, "del-idx-state")
			require.NoError(t, err)
			assert.Equal(t, "del-idx-state", got.StateId)
		})

		t.Run("index rejects empty key components", func(t *testing.T) {
			t.Parallel()

			tests := []struct {
				name    string
				userID  string
				host    string
				stateID string
			}{
				{"empty user_id", "", "host", "state"},
				{"empty host", "user", "", "state"},
				{"empty state_id", "user", "host", ""},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					t.Parallel()

					err := storage.PutPendingUpstreamAuthIndex(ctx, tt.userID, tt.host, tt.stateID)
					assert.Error(t, err)
				})
			}
		})
	})
}
