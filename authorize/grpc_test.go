//go:generate protoc -I ../internal/grpc/authorize/ --go_out=plugins=grpc:../internal/grpc/authorize/ ../internal/grpc/authorize/authorize.proto

package authorize

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/mock"
	"github.com/pomerium/pomerium/internal/grpc/authorize"
)

func TestAuthorize_IsAuthorized(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pe      evaluator.Evaluator
		in      *authorize.IsAuthorizedRequest
		want    *authorize.IsAuthorizedReply
		wantErr bool
	}{
		{"want false", &mock.PolicyEvaluator{}, &authorize.IsAuthorizedRequest{}, &authorize.IsAuthorizedReply{IsValid: false}, false},
		{"want true", &mock.PolicyEvaluator{IsAuthorizedResponse: true}, &authorize.IsAuthorizedRequest{}, &authorize.IsAuthorizedReply{IsValid: true}, false},
		{"want err", &mock.PolicyEvaluator{IsAuthorizedErr: errors.New("err")}, &authorize.IsAuthorizedRequest{}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authorize{
				pe: tt.pe,
			}
			got, err := a.IsAuthorized(context.TODO(), tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authorize.IsAuthorized() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authorize.IsAuthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorize_IsAdmin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pe      evaluator.Evaluator
		in      *authorize.IsAdminRequest
		want    *authorize.IsAdminReply
		wantErr bool
	}{
		{"want false", &mock.PolicyEvaluator{}, &authorize.IsAdminRequest{}, &authorize.IsAdminReply{IsValid: false}, false},
		{"want true", &mock.PolicyEvaluator{IsAdminResponse: true}, &authorize.IsAdminRequest{}, &authorize.IsAdminReply{IsValid: true}, false},
		{"want err", &mock.PolicyEvaluator{IsAdminErr: errors.New("err")}, &authorize.IsAdminRequest{}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authorize{
				pe: tt.pe,
			}
			got, err := a.IsAdmin(context.TODO(), tt.in)
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
