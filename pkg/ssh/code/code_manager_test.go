package code

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func newSbr(id string, sbr *session.SessionBindingRequest) *databroker.Record {
	return &databroker.Record{
		Type: grpcutil.GetTypeURL(sbr),
		Id:   id,
		Data: protoutil.NewAny(sbr),
	}
}

func TestCodeManager(t *testing.T) {
	c := newCodeManager(nil)

	all := []*databroker.Record{
		newSbr("c1", &session.SessionBindingRequest{
			Protocol:  "ssh",
			State:     session.SessionBindingRequestState_InFlight,
			Key:       "b1",
			CreatedAt: timestamppb.New(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour)),
		}),
	}
	c.UpdateRecords(t.Context(), 0, all)

	st, ok := c.GetByCodeID("c1")
	assert.True(t, ok)
	assert.Equal(t, "c1", st.Code)
	assert.Equal(t, "b1", st.BindingKey)
	assert.Equal(t, session.SessionBindingRequestState_InFlight, st.State)

	c.clearExpiredLocked()
	_, ok = c.GetByCodeID("c1")
	assert.False(t, ok)

	start, end := timestamppb.Now(), timestamppb.New(time.Now().Add(time.Hour))

	c.UpdateRecords(t.Context(), 0, []*databroker.Record{
		newSbr("c2", &session.SessionBindingRequest{
			Protocol:  "ssh",
			State:     session.SessionBindingRequestState_InFlight,
			Key:       "b2",
			CreatedAt: start,
			ExpiresAt: end,
		}),
	})

	c.clearExpiredLocked()

	st, ok = c.GetByCodeID("c2")
	assert.True(t, ok)
	assert.Equal(t, "c2", st.Code)
	assert.Equal(t, "b2", st.BindingKey)
	assert.Equal(t, session.SessionBindingRequestState_InFlight, st.State)

	c.UpdateRecords(t.Context(), 0, []*databroker.Record{
		newSbr("c2", &session.SessionBindingRequest{
			Protocol:  "ssh",
			State:     session.SessionBindingRequestState_Revoked,
			Key:       "b2",
			CreatedAt: start,
			ExpiresAt: end,
		}),
	})

	st, ok = c.GetByCodeID("c2")
	assert.True(t, ok)
	assert.Equal(t, "c2", st.Code)
	assert.Equal(t, "b2", st.BindingKey)
	assert.Equal(t, session.SessionBindingRequestState_Revoked, st.State)

	c.UpdateRecords(t.Context(), 0, []*databroker.Record{
		newSbr("c2", &session.SessionBindingRequest{
			Protocol:  "ssh",
			State:     session.SessionBindingRequestState_Accepted,
			Key:       "b2",
			CreatedAt: start,
			ExpiresAt: end,
		}),
	})

	st, ok = c.GetByCodeID("c2")
	assert.True(t, ok)
	assert.Equal(t, "c2", st.Code)
	assert.Equal(t, "b2", st.BindingKey)
	assert.Equal(t, session.SessionBindingRequestState_Accepted, st.State)
}
