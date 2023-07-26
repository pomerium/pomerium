package authorize

import (
	"bytes"
	"context"
	"strings"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func Test_populateLogEvent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = requestid.WithValue(ctx, "REQUEST-ID")

	checkRequest := &envoy_service_auth_v3.CheckRequest{
		Attributes: &envoy_service_auth_v3.AttributeContext{
			Request: &envoy_service_auth_v3.AttributeContext_Request{
				Http: &envoy_service_auth_v3.AttributeContext_HttpRequest{
					Host:   "HOST",
					Path:   "https://www.example.com/some/path?a=b",
					Method: "GET",
				},
			},
			Source: &envoy_service_auth_v3.AttributeContext_Peer{
				Address: &envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Address: "127.0.0.1",
						},
					},
				},
			},
		},
	}
	headers := map[string]string{"X-Request-Id": "CHECK-REQUEST-ID"}
	s := &session.Session{
		Id: "SESSION-ID",
		IdToken: &session.IDToken{
			Raw: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2OTAzMTU4NjIsImV4cCI6MTcyMTg1MTg2MiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.AAojgaG0fjMFwMCAC6YALHHMFIZEedFSP_vMGhiHhso",
		},
	}
	sa := &user.ServiceAccount{
		Id: "SERVICE-ACCOUNT-ID",
	}
	u := &user.User{
		Id:    "USER-ID",
		Email: "EMAIL",
	}
	impersonateDetails := &impersonateDetails{
		email:     "IMPERSONATE-EMAIL",
		sessionID: "IMPERSONATE-SESSION-ID",
		userID:    "IMPERSONATE-USER-ID",
	}

	for _, tc := range []struct {
		field  log.AuthorizeLogField
		s      sessionOrServiceAccount
		expect string
	}{
		{log.AuthorizeLogFieldCheckRequestID, s, `{"check-request-id":"CHECK-REQUEST-ID"}`},
		{log.AuthorizeLogFieldEmail, s, `{"email":"EMAIL"}`},
		{log.AuthorizeLogFieldHost, s, `{"host":"HOST"}`},
		{log.AuthorizeLogFieldIDToken, s, `{"id-token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE2OTAzMTU4NjIsImV4cCI6MTcyMTg1MTg2MiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.AAojgaG0fjMFwMCAC6YALHHMFIZEedFSP_vMGhiHhso"}`},
		{log.AuthorizeLogFieldIDTokenClaims, s, `{"id-token-claims":{"Email":"jrocket@example.com","GivenName":"Johnny","Role":["Manager","Project Administrator"],"Surname":"Rocket","aud":"www.example.com","exp":1721851862,"iat":1690315862,"iss":"Online JWT Builder","sub":"jrocket@example.com"}}`},
		{log.AuthorizeLogFieldImpersonateEmail, s, `{"impersonate-email":"IMPERSONATE-EMAIL"}`},
		{log.AuthorizeLogFieldImpersonateSessionID, s, `{"impersonate-session-id":"IMPERSONATE-SESSION-ID"}`},
		{log.AuthorizeLogFieldImpersonateUserID, s, `{"impersonate-user-id":"IMPERSONATE-USER-ID"}`},
		{log.AuthorizeLogFieldIP, s, `{"ip":"127.0.0.1"}`},
		{log.AuthorizeLogFieldMethod, s, `{"method":"GET"}`},
		{log.AuthorizeLogFieldPath, s, `{"path":"https://www.example.com/some/path"}`},
		{log.AuthorizeLogFieldQuery, s, `{"query":"a=b"}`},
		{log.AuthorizeLogFieldRequestID, s, `{"request-id":"REQUEST-ID"}`},
		{log.AuthorizeLogFieldServiceAccountID, sa, `{"service-account-id":"SERVICE-ACCOUNT-ID"}`},
		{log.AuthorizeLogFieldSessionID, s, `{"session-id":"SESSION-ID"}`},
		{log.AuthorizeLogFieldUser, s, `{"user":"USER-ID"}`},
	} {

		tc := tc
		t.Run(string(tc.field), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			log := zerolog.New(&buf)
			evt := log.Log()
			evt = populateLogEvent(ctx, tc.field, evt, checkRequest, tc.s, u, headers, impersonateDetails)
			evt.Send()

			assert.Equal(t, tc.expect, strings.TrimSpace(buf.String()))
		})
	}
}
