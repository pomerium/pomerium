package protoutil_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestUnknown(t *testing.T) {
	t.Parallel()

	d1 := durationpb.New(time.Second)
	d2 := durationpb.New(time.Minute)
	d3 := durationpb.New(time.Hour)
	err := protoutil.MarshalUnknownField(d1, 1000, d2)
	assert.NoError(t, err)
	err = protoutil.MarshalUnknownField(d1, 1000, d3)
	assert.NoError(t, err)
	var d4 durationpb.Duration
	found, err := protoutil.UnmarshalUnknownField(d1, 1000, &d4)
	assert.True(t, found)
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(d3, &d4, protocmp.Transform()),
		"should use last set unknown field")

	found, err = protoutil.UnmarshalUnknownField(d1, 1001, &d4)
	assert.False(t, found)
	assert.NoError(t, err)
}
