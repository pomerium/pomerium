package usagereporter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/zero/cluster"
)

type mockAPI struct {
	reportUsage func(ctx context.Context, req cluster.ReportUsageRequest) error
}

func (m mockAPI) ReportUsage(ctx context.Context, req cluster.ReportUsageRequest) error {
	return m.reportUsage(ctx, req)
}

func TestUsageReporter(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	t.Cleanup(clearTimeout)

	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)

	cc := testutil.NewGRPCServer(t, func(srv *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(srv, databroker.New())
	})
	t.Cleanup(func() { cc.Close() })

	tm1 := time.Date(2024, time.September, 11, 11, 56, 0, 0, time.UTC)

	requests := make(chan cluster.ReportUsageRequest, 1)

	client := databrokerpb.NewDataBrokerServiceClient(cc)
	ur := New(mockAPI{
		reportUsage: func(ctx context.Context, req cluster.ReportUsageRequest) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case requests <- req:
			}
			return nil
		},
	}, []byte("bQjwPpxcwJRbvsSMFgbZFkXmxFJ"), time.Millisecond*100)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return ur.Run(ctx, client)
	})
	eg.Go(func() error {
		_, err := databrokerpb.Put(ctx, client,
			&session.Session{
				Id:       "S1a",
				UserId:   "U1",
				IssuedAt: timestamppb.New(tm1),
			},
			&session.Session{
				Id:       "S1b",
				UserId:   "U1",
				IssuedAt: timestamppb.New(tm1),
			})
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case req := <-requests:
			assert.Equal(t, cluster.ReportUsageRequest{
				Users: []cluster.ReportUsageUser{{
					LastSignedInAt: tm1,
					PseudonymousId: "095xqqsjEEgYf5Yf+TAjWjooMQyh6jSV5SCPGe9eqvg=",
				}},
			}, req, "should send a single usage record")
		}

		_, err = databrokerpb.Put(ctx, client,
			&user.User{
				Id:    "U1",
				Email: "u1@example.com",
			})
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case req := <-requests:
			assert.Equal(t, cluster.ReportUsageRequest{
				Users: []cluster.ReportUsageUser{{
					LastSignedInAt:    tm1,
					PseudonymousEmail: "iq8/fj+uZaKitkWY12JIQgKJ5KIP+E0Cmy/HpxpdBXY=",
					PseudonymousId:    "095xqqsjEEgYf5Yf+TAjWjooMQyh6jSV5SCPGe9eqvg=",
				}},
			}, req, "should send another usage record with the email set")
		}

		cancel()
		return nil
	})
	err := eg.Wait()
	if err != nil && !errors.Is(ctx.Err(), context.Canceled) {
		assert.NoError(t, err)
	}
}

func Test_convertUsageReporterRecords(t *testing.T) {
	t.Parallel()

	tm1 := time.Date(2024, time.September, 11, 11, 56, 0, 0, time.UTC)

	assert.Empty(t, convertUsageReporterRecords([]byte("XXX"), nil))
	assert.Equal(t, []cluster.ReportUsageUser{{
		LastSignedInAt:    tm1,
		PseudonymousId:    "T9V1yL/UueF/LVuF6XjoSNde0INElXG10zKepmyPke8=",
		PseudonymousEmail: "8w5rtnZyv0EGkpHmTlkmupgb1jCzn/IxGCfvpdGGnvI=",
	}}, convertUsageReporterRecords([]byte("XXX"), []usageReporterRecord{{
		userID:         "ID",
		userEmail:      "EMAIL@example.com",
		lastSignedInAt: tm1,
	}}))
	assert.Equal(t, []cluster.ReportUsageUser{{
		LastSignedInAt: tm1,
		PseudonymousId: "T9V1yL/UueF/LVuF6XjoSNde0INElXG10zKepmyPke8=",
	}}, convertUsageReporterRecords([]byte("XXX"), []usageReporterRecord{{
		userID:         "ID",
		lastSignedInAt: tm1,
	}}), "should leave empty email")
}

func Test_latest(t *testing.T) {
	t.Parallel()

	tm1 := time.Date(2024, time.September, 11, 11, 56, 0, 0, time.UTC)
	tm2 := time.Date(2024, time.September, 12, 11, 56, 0, 0, time.UTC)

	assert.Equal(t, tm2, latest(tm1, tm2))
	assert.Equal(t, tm2, latest(tm2, tm1), "should ignore ordering")
	assert.Equal(t, tm1, latest(tm1, time.Time{}), "should handle zero time")
}
