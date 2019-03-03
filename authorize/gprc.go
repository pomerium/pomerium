//go:generate protoc -I ../proto/authorize --go_out=plugins=grpc:../proto/authorize ../proto/authorize/authorize.proto

package authorize // import "github.com/pomerium/pomerium/authorize"
import (
	"context"

	pb "github.com/pomerium/pomerium/proto/authorize"

	"github.com/pomerium/pomerium/internal/log"
)

// Authorize validates the user identity, device, and context of a request for
// a given route. Currently only checks identity.
func (a *Authorize) Authorize(ctx context.Context, in *pb.AuthorizeRequest) (*pb.AuthorizeReply, error) {
	ok := a.ValidIdentity(in.Route, &Identity{in.User, in.Email, in.Groups})
	log.Debug().Str("route", in.Route).Strs("groups", in.Groups).Str("email", in.Email).Bool("Valid?", ok).Msg("authorize/grpc")
	return &pb.AuthorizeReply{IsValid: ok}, nil
}
