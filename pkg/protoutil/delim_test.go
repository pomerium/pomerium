package protoutil_test

import (
	"testing"
	_ "unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/pkg/grpc/testproto"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

//go:linkname protobufRandSeed google.golang.org/protobuf/internal/detrand.randSeed
var protobufRandSeed int

// Forces the protojson format to be encoded in stable manner for testing:
//
//	https://github.com/golang/protobuf/issues/1121
func init() {
	protobufRandSeed = 0
}

func TestProtoDelim(t *testing.T) {
	msgs := []*testproto.Test{
		{
			StringField: "foo",
			ProtoField: &testproto.EmbeddedMessage{
				AnotherStringField: "bar",
			},
		},
		{
			StringField: "bar",
			ProtoField: &testproto.EmbeddedMessage{
				AnotherStringField: "foo",
			},
		},
	}
	data, err := protoutil.MarshalLengthDelimited(msgs)
	require.NoError(t, err)

	retmsgs, err := protoutil.UnmarshalLengthDelimited[*testproto.Test](data)
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(msgs, retmsgs, protocmp.Transform()))
}

func TestProtoJSON(t *testing.T) {
	msgs := []*testproto.Test{
		{
			StringField: "foo",
			ProtoField: &testproto.EmbeddedMessage{
				AnotherStringField: "bar",
			},
		},
		{
			StringField: "bar",
			ProtoField: &testproto.EmbeddedMessage{
				AnotherStringField: "foo",
			},
		},
	}

	data, err := protoutil.MarshalNewLineDelimitedProtoJSON(msgs)
	require.NoError(t, err)

	retmsgs, err := protoutil.UnmarshalNewLineDelimitedProtoJSON[*testproto.Test](data)
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(msgs, retmsgs, protocmp.Transform()))

	// should look like ndjson
	assert.Equal(t, string(data),
		`{"string_field":"foo","proto_field":{"another_string_field":"bar"}}
{"string_field":"bar","proto_field":{"another_string_field":"foo"}}
`)
}
