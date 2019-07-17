//go:generate protoc -I ../proto/authorize --go_out=plugins=grpc:../proto/authorize ../proto/authorize/authorize.proto

package authorize // import "github.com/pomerium/pomerium/authorize"
import (
	"context"

	"github.com/pomerium/pomerium/internal/telemetry"
	pb "github.com/pomerium/pomerium/proto/authorize"
)

// Authorize validates the user identity, device, and context of a request for
// a given route. Currently only checks identity.
func (a *Authorize) Authorize(ctx context.Context, in *pb.Identity) (*pb.AuthorizeReply, error) {
	_, span := telemetry.StartSpan(ctx, "authorize.grpc.Authorize")
	defer span.End()

	ok := a.ValidIdentity(in.Route,
		&Identity{
			User:              in.User,
			Email:             in.Email,
			Groups:            in.Groups,
			ImpersonateEmail:  in.ImpersonateEmail,
			ImpersonateGroups: in.ImpersonateGroups,
		})
	return &pb.AuthorizeReply{IsValid: ok}, nil
}

// IsAdmin validates the user is an administrative user.
func (a *Authorize) IsAdmin(ctx context.Context, in *pb.Identity) (*pb.IsAdminReply, error) {
	_, span := telemetry.StartSpan(ctx, "authorize.grpc.IsAdmin")
	defer span.End()
	ok := a.identityAccess.IsAdmin(
		&Identity{
			Email:  in.Email,
			Groups: in.Groups,
		})
	return &pb.IsAdminReply{IsAdmin: ok}, nil
}
