//go:generate protoc -I ../internal/grpc/authorize/ --go_out=plugins=grpc:../internal/grpc/authorize/ ../internal/grpc/authorize/authorize.proto

package authorize // import "github.com/pomerium/pomerium/authorize"
import (
	"context"

	"github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

// Authorize validates the user identity, device, and context of a request for
// a given route. Currently only checks identity.
func (a *Authorize) Authorize(ctx context.Context, in *authorize.Identity) (*authorize.AuthorizeReply, error) {
	_, span := trace.StartSpan(ctx, "authorize.grpc.Authorize")
	defer span.End()

	ok := a.ValidIdentity(in.Route,
		&Identity{
			User:              in.User,
			Email:             in.Email,
			Groups:            in.Groups,
			ImpersonateEmail:  in.ImpersonateEmail,
			ImpersonateGroups: in.ImpersonateGroups,
		})
	return &authorize.AuthorizeReply{IsValid: ok}, nil
}

// IsAdmin validates the user is an administrative user.
func (a *Authorize) IsAdmin(ctx context.Context, in *authorize.Identity) (*authorize.IsAdminReply, error) {
	_, span := trace.StartSpan(ctx, "authorize.grpc.IsAdmin")
	defer span.End()
	ok := a.identityAccess.IsAdmin(
		&Identity{
			Email:  in.Email,
			Groups: in.Groups,
		})
	return &authorize.IsAdminReply{IsAdmin: ok}, nil
}
