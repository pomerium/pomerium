package protoutil

import (
	"testing"

	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestMergeWithFieldMask(t *testing.T) {
	m1 := NewAny(&envoy_type_v3.SemanticVersion{
		MajorNumber: 1,
		MinorNumber: 1,
		Patch:       1,
	})
	m2 := NewAny(&envoy_type_v3.SemanticVersion{
		MajorNumber: 2,
		MinorNumber: 2,
		Patch:       2,
	})
	expect := NewAny(&envoy_type_v3.SemanticVersion{
		MajorNumber: 2,
		MinorNumber: 1,
		Patch:       2,
	})
	actual, err := MergeAnyWithFieldMask(m1, m2, &fieldmaskpb.FieldMask{
		Paths: []string{"major_number", "patch"},
	})
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(expect, actual, protocmp.Transform()))
}
