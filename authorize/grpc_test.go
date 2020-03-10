package authorize

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/authorize/evaluator/mock_evaluator"
	"github.com/pomerium/pomerium/internal/grpc/authorize"
)

func TestAuthorize_IsAuthorized(t *testing.T) {

	tests := []struct {
		name    string
		retDec  *authorize.IsAuthorizedReply
		retErr  error
		ctx     context.Context
		in      *authorize.IsAuthorizedRequest
		want    *authorize.IsAuthorizedReply
		wantErr bool
	}{
		{"good", &authorize.IsAuthorizedReply{}, nil, context.TODO(), &authorize.IsAuthorizedRequest{UserToken: "good"}, &authorize.IsAuthorizedReply{}, false},
		{"error", &authorize.IsAuthorizedReply{}, errors.New("error"), context.TODO(), &authorize.IsAuthorizedRequest{UserToken: "good"}, &authorize.IsAuthorizedReply{}, true},
		{"headers", &authorize.IsAuthorizedReply{}, nil, context.TODO(), &authorize.IsAuthorizedRequest{UserToken: "good", RequestHeaders: nil}, &authorize.IsAuthorizedReply{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			pe := mock_evaluator.NewMockEvaluator(mockCtrl)
			pe.EXPECT().IsAuthorized(gomock.Any(), gomock.Any()).Return(tt.retDec, tt.retErr).AnyTimes()

			a := &Authorize{
				pe: pe,
			}
			got, err := a.IsAuthorized(tt.ctx, tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authorize.IsAuthorized() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Authorize.IsAuthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}
