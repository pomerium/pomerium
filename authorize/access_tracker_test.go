package authorize

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type testAccessTrackerProvider struct {
	dataBrokerServiceClient databroker.DataBrokerServiceClient
}

func (provider *testAccessTrackerProvider) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return provider.dataBrokerServiceClient
}

func TestAccessTracker(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var mu sync.Mutex
	sessions := map[string]*session.Session{
		"session-0": {
			Id: "session-0",
		},
		"session-1": {
			Id: "session-1",
		},
		"session-2": {
			Id: "session-2",
		},
	}
	serviceAccounts := map[string]*user.ServiceAccount{
		"service-account-0": {
			Id: "service-account-0",
		},
		"service-account-1": {
			Id: "service-account-1",
		},
		"service-account-2": {
			Id: "service-account-2",
		},
	}
	tracker := NewAccessTracker(&testAccessTrackerProvider{
		dataBrokerServiceClient: &mockDataBrokerServiceClient{
			get: func(_ context.Context, in *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
				mu.Lock()
				defer mu.Unlock()

				switch in.GetType() {
				case "type.googleapis.com/session.Session":
					s, ok := sessions[in.GetId()]
					if !ok {
						return nil, databroker.ErrRecordNotFound
					}
					return &databroker.GetResponse{
						Record: &databroker.Record{
							Type: in.GetType(),
							Id:   in.GetId(),
							Data: protoutil.NewAny(s),
						},
					}, nil
				case "type.googleapis.com/user.ServiceAccount":
					sa, ok := serviceAccounts[in.GetId()]
					if !ok {
						return nil, databroker.ErrRecordNotFound
					}
					return &databroker.GetResponse{
						Record: &databroker.Record{
							Type: in.GetType(),
							Id:   in.GetId(),
							Data: protoutil.NewAny(sa),
						},
					}, nil
				default:
					return nil, status.Errorf(codes.InvalidArgument, "unknown type: %s", in.GetType())
				}
			},
			put: func(_ context.Context, in *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
				mu.Lock()
				defer mu.Unlock()

				res := new(databroker.PutResponse)
				for _, record := range in.GetRecords() {
					switch record.GetType() {
					case "type.googleapis.com/session.Session":
						data, _ := record.GetData().UnmarshalNew()
						sessions[record.GetId()] = data.(*session.Session)
						res.Records = append(res.Records, &databroker.Record{
							Type: record.GetType(),
							Id:   record.GetId(),
							Data: protoutil.NewAny(data),
						})
					case "type.googleapis.com/user.ServiceAccount":
						data, _ := record.GetData().UnmarshalNew()
						serviceAccounts[record.GetId()] = data.(*user.ServiceAccount)
						res.Records = append(res.Records, &databroker.Record{
							Type: record.GetType(),
							Id:   record.GetId(),
							Data: protoutil.NewAny(data),
						})
					default:
						return nil, status.Errorf(codes.InvalidArgument, "unknown type: %s", record.GetType())
					}
				}
				return res, nil
			},
		},
	}, 200, time.Second)
	go tracker.Run(ctx)

	for i := 0; i < 100; i++ {
		tracker.TrackSessionAccess(fmt.Sprintf("session-%d", i%3))
	}
	for i := 0; i < 100; i++ {
		tracker.TrackServiceAccountAccess(fmt.Sprintf("service-account-%d", i%3))
	}

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()

		return sessions["session-0"].GetAccessedAt().IsValid() &&
			sessions["session-1"].GetAccessedAt().IsValid() &&
			sessions["session-2"].GetAccessedAt().IsValid() &&
			serviceAccounts["service-account-0"].GetAccessedAt().IsValid() &&
			serviceAccounts["service-account-1"].GetAccessedAt().IsValid() &&
			serviceAccounts["service-account-2"].GetAccessedAt().IsValid()
	}, time.Second*10, time.Millisecond*100)
}
