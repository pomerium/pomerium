//go:generate protoc -I ../proto/authorize --go_out=plugins=grpc:../proto/authorize ../proto/authorize/authorize.proto

package authorize // import "github.com/pomerium/pomerium/authorize"
import (
	"context"

	pb "github.com/pomerium/pomerium/proto/authorize"
)

// Authorize validates the user identity, device, and context of a request for
// a given route. Currently only checks identity.
func (a *Authorize) Authorize(ctx context.Context, in *pb.AuthorizeRequest) (*pb.AuthorizeReply, error) {
	ok := a.ValidIdentity(in.Route, &Identity{in.User, in.Email, in.Groups})
	return &pb.AuthorizeReply{IsValid: ok}, nil
}
