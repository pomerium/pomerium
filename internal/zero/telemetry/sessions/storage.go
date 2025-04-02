package sessions

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const (
	metricStateTypeURL = "pomerium.io/ActiveUsersMetricState"
)

// SaveMetricState saves the state of a metric to the databroker
func SaveMetricState(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	id string,
	data []byte,
	value uint,
	lastReset time.Time,
) error {
	_, err := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: metricStateTypeURL,
			Id:   id,
			Data: (&MetricState{
				Data:      data,
				LastReset: lastReset,
				Count:     value,
			}).ToAny(),
		}},
	})
	return err
}

// LoadMetricState loads the state of a metric from the databroker
func LoadMetricState(
	ctx context.Context, client databroker.DataBrokerServiceClient, id string,
) (*MetricState, error) {
	resp, err := client.Get(ctx, &databroker.GetRequest{
		Type: metricStateTypeURL,
		Id:   id,
	})
	if err != nil {
		return nil, fmt.Errorf("load metric state: %w", err)
	}

	var state MetricState
	err = state.FromAny(resp.GetRecord().GetData())
	if err != nil {
		return nil, fmt.Errorf("load metric state: %w", err)
	}

	return &state, nil
}

// MetricState is the persistent state of a metric
type MetricState struct {
	Data      []byte
	LastReset time.Time
	Count     uint
}

const (
	countKey     = "count"
	dataKey      = "data"
	lastResetKey = "last_reset"
)

// ToAny marshals a MetricState into an anypb.Any
func (r *MetricState) ToAny() *anypb.Any {
	return protoutil.NewAny(&structpb.Struct{
		Fields: map[string]*structpb.Value{
			countKey:     structpb.NewNumberValue(float64(r.Count)),
			dataKey:      structpb.NewStringValue(base64.StdEncoding.EncodeToString(r.Data)),
			lastResetKey: structpb.NewStringValue(r.LastReset.Format(time.RFC3339)),
		},
	})
}

// FromAny unmarshals an anypb.Any into a MetricState
func (r *MetricState) FromAny(a *anypb.Any) error {
	var s structpb.Struct
	err := a.UnmarshalTo(&s)
	if err != nil {
		return fmt.Errorf("unmarshal struct: %w", err)
	}

	vData, ok := s.GetFields()[dataKey]
	if !ok {
		return fmt.Errorf("missing %s field", dataKey)
	}
	data, err := base64.StdEncoding.DecodeString(vData.GetStringValue())
	if err != nil {
		return fmt.Errorf("decode state: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}

	vLastReset, ok := s.GetFields()[lastResetKey]
	if !ok {
		return fmt.Errorf("missing %s field", lastResetKey)
	}
	lastReset, err := time.Parse(time.RFC3339, vLastReset.GetStringValue())
	if err != nil {
		return fmt.Errorf("parse last reset: %w", err)
	}
	vCount, ok := s.GetFields()[countKey]
	if !ok {
		return fmt.Errorf("missing %s field", countKey)
	}

	r.Data = data
	r.LastReset = lastReset
	r.Count = uint(vCount.GetNumberValue())

	return nil
}
