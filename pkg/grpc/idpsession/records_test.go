package idpsession

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestNewBoundRecords(t *testing.T) {
	records := NewBoundRecords(
		"upstream-session",
		BindingProtocol_BINDING_PROTOCOL_BROWSER,
		map[string]string{"user-agent": "test-browser/1.0"},
		&session.Session{Id: "session-id"},
	)
	require.Len(t, records, 2)

	assert.Equal(t, "type.googleapis.com/session.Session", records[0].GetType())
	assert.Equal(t, "session-id", records[0].GetId())

	var binding Binding
	require.NoError(t, records[1].GetData().UnmarshalTo(&binding))
	assert.Equal(t, "session-id", binding.GetId())
	assert.Equal(t, "type.googleapis.com/session.Session", binding.GetTypeUrl())
	assert.Equal(t, "upstream-session", binding.GetIdpSessionId())
	assert.Equal(t, BindingProtocol_BINDING_PROTOCOL_BROWSER, binding.GetProtocol())
	assert.Equal(t, "test-browser/1.0", binding.GetDetails()["user-agent"])
}
