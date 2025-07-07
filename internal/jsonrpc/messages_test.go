package jsonrpc

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRequest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		data    string
		wantID  any
		wantErr string
	}{
		{"number ID", `{"jsonrpc":"2.0","id":123,"method":"test_method"}`, json.Number("123"), ""},
		{"string ID", `{"jsonrpc":"2.0","id":"abc-123","method":"test_method"}`, "abc-123", ""},
		{"UUID ID", `{"jsonrpc":"2.0","id":"550e8400-e29b-41d4-a716-446655440000","method":"test_method"}`, "550e8400-e29b-41d4-a716-446655440000", ""},
		{"large number ID", `{"jsonrpc":"2.0","id":9007199254740993,"method":"test_method"}`, json.Number("9007199254740993"), ""},
		{"null ID", `{"jsonrpc":"2.0","id":null,"method":"test_method"}`, nil, ""},
		{"notification", `{"jsonrpc":"2.0","method":"test_method"}`, nil, ""},
		{"invalid JSON", `{"jsonrpc":"2.0","id":123,"method":}`, nil, "failed to parse JSON-RPC request"},
		{"invalid version", `{"jsonrpc":"1.0","id":123,"method":"test_method"}`, nil, "invalid JSON-RPC version"},
		{"missing method", `{"jsonrpc":"2.0","id":123}`, nil, "missing method"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := ParseRequest([]byte(tc.data))
			if tc.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "2.0", req.JSONRPC)
			assert.Equal(t, "test_method", req.Method)
			if tc.wantID == nil {
				assert.True(t, req.ID.IsZero() || req.ID.value == nil)
			} else {
				assert.Equal(t, tc.wantID, req.ID.value)
			}
		})
	}
}

func TestID_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		input   string
		want    any
		wantErr string
	}{
		{"string", `"test-id"`, "test-id", ""},
		{"UUID", `"550e8400-e29b-41d4-a716-446655440000"`, "550e8400-e29b-41d4-a716-446655440000", ""},
		{"number", `123`, json.Number("123"), ""},
		{"large number", `9007199254740993`, json.Number("9007199254740993"), ""},
		{"null", `null`, nil, ""},
		{"invalid bool", `true`, nil, "field 'id' must be a string, number, or null"},
		{"invalid array", `[1,2,3]`, nil, "field 'id' must be a string, number, or null"},
		{"invalid object", `{"key":"value"}`, nil, "field 'id' must be a string, number, or null"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var id ID
			err := json.Unmarshal([]byte(tc.input), &id)
			if tc.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, id.value)
		})
	}
}

func TestID_MarshalJSON(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		id   ID
		want string
	}{
		{"string", NewStringID("test-id"), `"test-id"`},
		{"UUID", NewStringID("550e8400-e29b-41d4-a716-446655440000"), `"550e8400-e29b-41d4-a716-446655440000"`},
		{"number", NewNumberID(123), `123`},
		{"large number", NewJSONNumberID(json.Number("9007199254740993")), `9007199254740993`},
		{"null", ID{value: nil}, `null`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.id)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(data))
		})
	}
}

func TestID_IsZero(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		id   ID
		want bool
	}{
		{"zero", ID{value: nil}, true},
		{"string", NewStringID("test"), false},
		{"empty string", NewStringID(""), false},
		{"number", NewNumberID(123), false},
		{"zero number", NewNumberID(0), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.id.IsZero())
		})
	}
}

func TestRoundTripMarshaling(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		json string
	}{
		{"string ID", `{"jsonrpc":"2.0","id":"test-123","method":"test"}`},
		{"UUID ID", `{"jsonrpc":"2.0","id":"550e8400-e29b-41d4-a716-446655440000","method":"test"}`},
		{"number ID", `{"jsonrpc":"2.0","id":123,"method":"test"}`},
		{"large number ID", `{"jsonrpc":"2.0","id":9007199254740993,"method":"test"}`},
		{"null ID", `{"jsonrpc":"2.0","id":null,"method":"test"}`},
		{"max int64", `{"jsonrpc":"2.0","id":9223372036854775807,"method":"test"}`},
		{"min int64", `{"jsonrpc":"2.0","id":-9223372036854775808,"method":"test"}`},
		{"very large", `{"jsonrpc":"2.0","id":123456789012345678901234567890,"method":"test"}`},
		{"decimal", `{"jsonrpc":"2.0","id":123.456,"method":"test"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := ParseRequest([]byte(tc.json))
			require.NoError(t, err)

			marshaled, err := json.Marshal(req)
			require.NoError(t, err)

			req2, err := ParseRequest(marshaled)
			require.NoError(t, err)

			assert.Equal(t, req.JSONRPC, req2.JSONRPC)
			assert.Equal(t, req.Method, req2.Method)
			assert.Equal(t, req.ID.value, req2.ID.value)
		})
	}
}

func TestSpecialIDCases(t *testing.T) {
	t.Parallel()

	t.Run("UUID in various formats", func(t *testing.T) {
		testCases := []string{
			"550e8400-e29b-41d4-a716-446655440000",
			"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			"00000000-0000-0000-0000-000000000000",
			"ffffffff-ffff-ffff-ffff-ffffffffffff",
			"123e4567-e89b-12d3-a456-426614174000",
		}

		for _, uuid := range testCases {
			t.Run("UUID_"+uuid, func(t *testing.T) {
				jsonStr := fmt.Sprintf(`{"jsonrpc":"2.0","id":"%s","method":"test"}`, uuid)
				req, err := ParseRequest([]byte(jsonStr))
				require.NoError(t, err)
				assert.Equal(t, uuid, req.ID.value)

				marshaled, err := json.Marshal(req)
				require.NoError(t, err)

				req2, err := ParseRequest(marshaled)
				require.NoError(t, err)
				assert.Equal(t, uuid, req2.ID.value)
			})
		}
	})

	t.Run("alphanumeric string IDs", func(t *testing.T) {
		testCases := []string{
			"abc123",
			"request-456",
			"session_789",
			"tool-call-id-42",
			"mcp_request_2023_12_25",
			"user-action-12345-67890",
		}

		for _, id := range testCases {
			t.Run("ID_"+id, func(t *testing.T) {
				jsonStr := fmt.Sprintf(`{"jsonrpc":"2.0","id":"%s","method":"test"}`, id)
				req, err := ParseRequest([]byte(jsonStr))
				require.NoError(t, err)
				assert.Equal(t, id, req.ID.value)
			})
		}
	})

	t.Run("edge case numbers", func(t *testing.T) {
		testCases := []struct {
			name   string
			number string
		}{
			{"zero", "0"},
			{"negative", "-1"},
			{"small positive", "42"},
			{"javascript max safe integer", "9007199254740991"},
			{"javascript max safe integer + 1", "9007199254740992"},
			{"javascript max safe integer + 2", "9007199254740993"},
			{"very large positive", "999999999999999999999999999"},
			{"very large negative", "-999999999999999999999999999"},
			{"decimal would be invalid but let's see", "123.456"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				jsonStr := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"test"}`, tc.number)
				req, err := ParseRequest([]byte(jsonStr))
				require.NoError(t, err)
				assert.Equal(t, json.Number(tc.number), req.ID.value)

				marshaled, err := json.Marshal(req)
				require.NoError(t, err)

				req2, err := ParseRequest(marshaled)
				require.NoError(t, err)
				assert.Equal(t, json.Number(tc.number), req2.ID.value)
			})
		}
	})
}
