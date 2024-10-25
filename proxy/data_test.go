package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/testutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func Test_getUserInfoData(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	cc := testutil.NewGRPCServer(t, func(srv *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(srv, databroker.New(ctx))
	})
	t.Cleanup(func() { cc.Close() })

	client := databrokerpb.NewDataBrokerServiceClient(cc)

	opts := testOptions(t)
	proxy, err := New(ctx, &config.Config{Options: opts})
	require.NoError(t, err)
	proxy.state.Load().dataBrokerClient = client

	require.NoError(t, databrokerpb.PutMulti(ctx, client,
		makeRecord(&session.Session{
			Id:     "S1",
			UserId: "U1",
		}),
		makeRecord(&user.User{
			Id: "U1",
		}),
		makeRecord(&configpb.Config{
			Name: "dashboard-settings",
		}),
		makeStructRecord(directory.UserRecordType, "U1", map[string]any{
			"group_ids": []any{"G1", "G2", "G3"},
		})))

	r := httptest.NewRequest(http.MethodGet, "/.pomerium/", nil)
	r.Header.Set("Authorization", "Bearer Pomerium-"+encodeSession(t, opts, &sessions.State{
		ID: "S1",
	}))
	data := proxy.getUserInfoData(r)
	assert.Equal(t, "S1", data.Session.Id)
	assert.Equal(t, "U1", data.User.Id)
	assert.True(t, data.IsEnterprise)
	assert.Equal(t, []string{"G1", "G2", "G3"}, data.DirectoryUser.GroupIDs)
}

func makeRecord(object interface {
	proto.Message
	GetId() string
},
) *databrokerpb.Record {
	a := protoutil.NewAny(object)
	return &databrokerpb.Record{
		Type:       a.GetTypeUrl(),
		Id:         object.GetId(),
		Data:       a,
		ModifiedAt: timestamppb.Now(),
	}
}

func makeStructRecord(recordType, recordID string, object any) *databrokerpb.Record {
	s := protoutil.ToStruct(object).GetStructValue()
	return &databrokerpb.Record{
		Type:       recordType,
		Id:         recordID,
		Data:       protoutil.NewAny(s),
		ModifiedAt: timestamppb.Now(),
	}
}
