// Package authenticateflow implements the core authentication flow. This
// includes creating and parsing sign-in redirect URLs, storing and retrieving
// session data, and handling authentication callback URLs.
package authenticateflow

import (
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

var outboundGRPCConnection = new(grpc.CachedOutboundGRPClientConn)

func populateUserFromClaims(u *user.User, claims map[string]interface{}) {
	if v, ok := claims["name"]; ok {
		u.Name = fmt.Sprint(v)
	}
	if v, ok := claims["email"]; ok {
		u.Email = fmt.Sprint(v)
	}
	if u.Claims == nil {
		u.Claims = make(map[string]*structpb.ListValue)
	}
	for k, vs := range identity.Claims(claims).Flatten().ToPB() {
		u.Claims[k] = vs
	}
}
