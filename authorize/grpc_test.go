package authorize

import (
	"context"
	"reflect"
	"testing"

	pb "github.com/pomerium/pomerium/internal/grpc/authorize"
)

func TestAuthorize_Authorize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		SharedKey      string
		identityAccess IdentityValidator
		in             *pb.Identity
		want           *pb.AuthorizeReply
		wantErr        bool
	}{
		{"valid authorization request", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", &MockIdentityValidator{ValidResponse: true}, &pb.Identity{Route: "http://pomerium.io", User: "user@pomerium.io"}, &pb.AuthorizeReply{IsValid: true}, false},
		{"invalid authorization request", "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y+lJU7B8=", &MockIdentityValidator{ValidResponse: false}, &pb.Identity{Route: "http://pomerium.io", User: "user@pomerium.io"}, &pb.AuthorizeReply{IsValid: false}, false},
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

func TestAuthorize_IsAdmin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		identityAccess IdentityValidator
		in             *pb.Identity
		want           *pb.IsAdminReply
		wantErr        bool
	}{
		{"valid authorization request", &MockIdentityValidator{IsAdminResponse: true}, &pb.Identity{Route: "http://pomerium.io", User: "user@pomerium.io"}, &pb.IsAdminReply{IsAdmin: true}, false},
		{"invalid authorization request", &MockIdentityValidator{IsAdminResponse: false}, &pb.Identity{Route: "http://pomerium.io", User: "user@pomerium.io"}, &pb.IsAdminReply{IsAdmin: false}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authorize{
				SharedKey:      "gXK6ggrlIW2HyKyUF9rUO4azrDgxhDPWqw9y",
				identityAccess: tt.identityAccess,
			}
			got, err := a.IsAdmin(context.Background(), tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authorize.IsAdmin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authorize.IsAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}
