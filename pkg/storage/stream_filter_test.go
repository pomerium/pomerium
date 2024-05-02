package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestRecordStreamFilterFromFilterExpression(t *testing.T) {
	type M = map[string]any

	s, err := structpb.NewStruct(M{
		"$index": M{
			"cidr": "192.168.0.0/16",
		},
	})
	require.NoError(t, err)
	f1, err := RecordStreamFilterFromFilterExpression(EqualsFilterExpression{
		Fields: []string{"$index"},
		Value:  "192.168.0.1",
	})
	if assert.NoError(t, err) {
		assert.True(t, f1(&databroker.Record{
			Data: protoutil.NewAny(s),
		}))
	}

	f2, err := RecordStreamFilterFromFilterExpression(EqualsFilterExpression{
		Fields: []string{"$index"},
		Value:  "192.169.0.1",
	})
	if assert.NoError(t, err) {
		assert.False(t, f2(&databroker.Record{
			Data: protoutil.NewAny(s),
		}))
	}
}
