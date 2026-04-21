package protoutil_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/pkg/grpc/testproto"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

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

	data, err := protoutil.MarshalLenghDelimitedProtojson(msgs)
	require.NoError(t, err)
	// should look like ndjson
	assert.Equal(t, string(data),
		`{"string_field":"foo","proto_field":{"another_string_field":"bar"}}
{"string_field":"bar","proto_field":{"another_string_field":"foo"}}
`)

	retmsgs, err := protoutil.UnmarshalLengthDelimitedProtojson[*testproto.Test](data)
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(msgs, retmsgs, protocmp.Transform()))
}
