package mock_authenticate_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	pb "github.com/pomerium/pomerium/proto/authenticate"

	mock "github.com/pomerium/pomerium/proto/authenticate/mock_authenticate"
)

var fixedDate = time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)

// rpcMsg implements the gomock.Matcher interface
type rpcMsg struct {
	msg proto.Message
}

func (r *rpcMsg) Matches(msg interface{}) bool {
	m, ok := msg.(proto.Message)
	if !ok {
		return false
	}
	return proto.Equal(m, r.msg)
}

func (r *rpcMsg) String() string {
	return fmt.Sprintf("is %s", r.msg)
}
func TestValidate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAuthenticateClient := mock.NewMockAuthenticatorClient(ctrl)
	req := &pb.ValidateRequest{IdToken: "unit_test"}
	mockAuthenticateClient.EXPECT().Validate(
		gomock.Any(),
		&rpcMsg{msg: req},
	).Return(&pb.ValidateReply{IsValid: false}, nil)
	testValidate(t, mockAuthenticateClient)
}

func testValidate(t *testing.T, client pb.AuthenticatorClient) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := client.Validate(ctx, &pb.ValidateRequest{IdToken: "unit_test"})
	if err != nil || r.IsValid != false {
		t.Errorf("mocking failed")
	}
	t.Log("Reply : ", r.IsValid)
}

func TestAuthenticate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAuthenticateClient := mock.NewMockAuthenticatorClient(ctrl)
	mockExpire, err := ptypes.TimestampProto(fixedDate)
	if err != nil {
		t.Fatalf("%v failed converting timestampe", err)
	}
	req := &pb.AuthenticateRequest{Code: "unit_test"}
	mockAuthenticateClient.EXPECT().Authenticate(
		gomock.Any(),
		&rpcMsg{msg: req},
	).Return(&pb.AuthenticateReply{
		AccessToken:  "mocked access token",
		RefreshToken: "mocked refresh token",
		IdToken:      "mocked id token",
		User:         "user1",
		Email:        "test@email.com",
		Expiry:       mockExpire,
	}, nil)
	testAuthenticate(t, mockAuthenticateClient)
}

func testAuthenticate(t *testing.T, client pb.AuthenticatorClient) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := client.Authenticate(ctx, &pb.AuthenticateRequest{Code: "unit_test"})
	if err != nil {
		t.Errorf("mocking failed %v", err)
	}
	if r.AccessToken != "mocked access token" {
		t.Errorf("authenticate: invalid access token")
	}
	if r.RefreshToken != "mocked refresh token" {
		t.Errorf("authenticate: invalid refresh token")
	}
	if r.IdToken != "mocked id token" {
		t.Errorf("authenticate: invalid id token")
	}
	if r.User != "user1" {
		t.Errorf("authenticate: invalid user")
	}
	if r.Email != "test@email.com" {
		t.Errorf("authenticate: invalid email")
	}
}

func TestRefresh(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRefreshClient := mock.NewMockAuthenticatorClient(ctrl)
	mockExpire, err := ptypes.TimestampProto(fixedDate)
	if err != nil {
		t.Fatalf("%v failed converting timestampe", err)
	}
	req := &pb.RefreshRequest{RefreshToken: "unit_test"}
	mockRefreshClient.EXPECT().Refresh(
		gomock.Any(),
		&rpcMsg{msg: req},
	).Return(&pb.RefreshReply{
		AccessToken: "mocked access token",
		Expiry:      mockExpire,
	}, nil)
	testRefresh(t, mockRefreshClient)
}

func testRefresh(t *testing.T, client pb.AuthenticatorClient) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := client.Refresh(ctx, &pb.RefreshRequest{RefreshToken: "unit_test"})
	if err != nil {
		t.Errorf("mocking failed %v", err)
	}
	if r.AccessToken != "mocked access token" {
		t.Errorf("Refresh: invalid access token")
	}
	respExpire, err := ptypes.Timestamp(r.Expiry)
	if err != nil {
		t.Fatalf("%v failed converting timestampe", err)
	}

	if respExpire != fixedDate {
		t.Errorf("Refresh: bad expiry got:%v want:%v", respExpire, fixedDate)
	}

}
