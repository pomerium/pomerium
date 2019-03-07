package clients

import (
	"context"
	"testing"

	"github.com/pomerium/pomerium/internal/sessions"
	pb "github.com/pomerium/pomerium/proto/authorize"
	"google.golang.org/grpc"
)

func TestAuthorizeGRPC_Authorize(t *testing.T) {
	type fields struct {
		Conn   *grpc.ClientConn
		client pb.AuthorizerClient
	}
	type args struct {
		ctx   context.Context
		route string
		s     *sessions.SessionState
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthorizeGRPC{
				Conn:   tt.fields.Conn,
				client: tt.fields.client,
			}
			got, err := a.Authorize(tt.args.ctx, tt.args.route, tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthorizeGRPC.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("AuthorizeGRPC.Authorize() = %v, want %v", got, tt.want)
			}
		})
	}
}
