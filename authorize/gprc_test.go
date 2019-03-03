//go:generate protoc -I ../proto/authorize --go_out=plugins=grpc:../proto/authorize ../proto/authorize/authorize.proto

package authorize

import (
	"context"
	"reflect"
	"testing"

	pb "github.com/pomerium/pomerium/proto/authorize"
)

func TestAuthorize_Authorize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		SharedKey      string
		identityAccess IdentityValidator
		in             *pb.AuthorizeRequest
		want           *pb.AuthorizeReply
		wantErr        bool
	}{
		{"valid authorization request", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", &MockIdentityValidator{ValidResponse: true}, &pb.AuthorizeRequest{Route: "http://pomerium.io", User: "user@pomerium.io"}, &pb.AuthorizeReply{IsValid: true}, false},
		{"invalid authorization request", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", &MockIdentityValidator{ValidResponse: false}, &pb.AuthorizeRequest{Route: "http://pomerium.io", User: "user@pomerium.io"}, &pb.AuthorizeReply{IsValid: false}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authorize{SharedKey: tt.SharedKey, identityAccess: tt.identityAccess}
			got, err := a.Authorize(context.Background(), tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authorize.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authorize.Authorize() = %v, want %v", got, tt.want)
			}
		})
	}
}
