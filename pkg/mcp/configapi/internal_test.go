package configapi

import (
	"encoding/json"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/dynamicpb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// TestConnectCodeFromWire_AllCodes is the round-trip of connect-go's wire
// serialization for every documented Code value, plus an unknown sentinel.
// Without this, only the happy paths exercised by TestErrorMapperRedactsQuota
// touch the function — 15 of 16 codes were silently untested before.
func TestConnectCodeFromWire_AllCodes(t *testing.T) {
	t.Parallel()

	// connect-go's *Error.JSONString uses lower_snake_case names that match
	// the wire format we receive from configconnect; the table is the
	// fixed contract on that side.
	cases := []struct {
		wire string
		want connect.Code
	}{
		{"canceled", connect.CodeCanceled},
		{"unknown", connect.CodeUnknown},
		{"invalid_argument", connect.CodeInvalidArgument},
		{"deadline_exceeded", connect.CodeDeadlineExceeded},
		{"not_found", connect.CodeNotFound},
		{"already_exists", connect.CodeAlreadyExists},
		{"permission_denied", connect.CodePermissionDenied},
		{"resource_exhausted", connect.CodeResourceExhausted},
		{"failed_precondition", connect.CodeFailedPrecondition},
		{"aborted", connect.CodeAborted},
		{"out_of_range", connect.CodeOutOfRange},
		{"unimplemented", connect.CodeUnimplemented},
		{"internal", connect.CodeInternal},
		{"unavailable", connect.CodeUnavailable},
		{"data_loss", connect.CodeDataLoss},
		{"unauthenticated", connect.CodeUnauthenticated},
		{"", connect.CodeUnknown},         // empty falls through to default
		{"???", connect.CodeUnknown},      // unrecognised falls through to default
		{"NOTFOUND", connect.CodeUnknown}, // case-sensitive → unknown
	}
	for _, tc := range cases {
		t.Run(tc.wire, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, connectCodeFromWire(tc.wire))
		})
	}
}

// TestIsJSONObject covers the byte-peek helper at every shape the recursive
// JSON-tree builder might encounter. The function decides whether a
// json.RawMessage encodes a JSON object — leading whitespace must not
// confuse it; non-objects (arrays, scalars, null, the empty string) must
// all return false.
func TestIsJSONObject(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want bool
	}{
		{`{}`, true},
		{`{"k":1}`, true},
		{`  {`, true},
		{"\t\n\r {", true},
		{`null`, false},
		{`  null`, false},
		{`[]`, false},
		{` [1,2]`, false},
		{`"hi"`, false},
		{`42`, false},
		{`true`, false},
		{``, false},
		{`   `, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isJSONObject(json.RawMessage(tc.in)))
		})
	}
}

// TestUnmarshalNested_FieldAbsent locks the contract that an Update payload
// missing the entity field surfaces a concrete "field … not present" error
// rather than a silent no-op merge. The happy path is exercised via the
// integration tests; this pins the negative side.
func TestUnmarshalNested_FieldAbsent(t *testing.T) {
	t.Parallel()

	dst := dynamicpb.NewMessage(
		(&configpb.Route{}).ProtoReflect().Descriptor(),
	)
	err := unmarshalNested([]byte(`{}`), "route", dst)
	assert.ErrorContains(t, err, `field "route" not present`)
}

// TestUintFromArg covers every shape the JSON-decoded `limit` argument can
// take. The PreCall reads this value to decide whether to clamp; a wrong
// "ok" decision either leaves the cap unenforced (security) or clamps a
// legitimate small limit to 100 (correctness).
func TestUintFromArg(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		in     any
		wantN  uint64
		wantOK bool
	}{
		{"nil", nil, 0, false},
		{"absent (zero-value any)", any(nil), 0, false},
		{"positive float", float64(42), 42, true},
		{"zero float", float64(0), 0, true},
		{"negative float", float64(-1), 0, false},
		{"numeric string", "123", 123, true},
		{"max-uint64 string", "18446744073709551615", 18446744073709551615, true},
		{"non-numeric string", "abc", 0, false},
		{"empty string", "", 0, false},
		{"unsupported type", []any{1, 2}, 0, false},
		{"bool", true, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n, ok := uintFromArg(tc.in)
			assert.Equal(t, tc.wantN, n)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

// TestExtractEntityIDFromJSON locks the contract that any malformed,
// missing, or non-string id surfaces as "" — the upstream caller treats ""
// as "no entity to fetch", short-circuiting the sparse-merge fallback.
// Hitting these branches catches a future change that, e.g., switches the
// proto's id field from string to bytes and accidentally accepts the
// type-mismatched value.
func TestExtractEntityIDFromJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"happy path", `{"route":{"id":"r-1","name":"x"}}`, "r-1"},
		{"absent topField", `{"policy":{"id":"p-1"}}`, ""},
		{"non-object inner", `{"route":"r-1"}`, ""},
		{"missing id", `{"route":{"name":"x"}}`, ""},
		{"non-string id", `{"route":{"id":42}}`, ""},
		{"malformed top-level", `{`, ""},
		{"empty input", ``, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, extractEntityIDFromJSON([]byte(tc.in), "route"))
		})
	}
}

// TestLookupKey covers the three possible outcomes: present by JSON name,
// present by proto (snake_case) name, or absent. The proto-name fallback
// supports an LLM that sends snake_case keys instead of the protojson
// camelCase the schema advertises.
func TestLookupKey(t *testing.T) {
	t.Parallel()

	routeFields := (&configpb.Route{}).ProtoReflect().Descriptor().Fields()
	idFD := routeFields.ByName("id")
	tlsClientKeyFD := routeFields.ByName("tls_client_key")

	t.Run("nil tree returns false", func(t *testing.T) {
		t.Parallel()
		sub, ok := lookupKey(nil, idFD)
		assert.False(t, ok)
		assert.Nil(t, sub)
	})
	t.Run("hit by JSON name", func(t *testing.T) {
		t.Parallel()
		sub, ok := lookupKey(jsonKeyNode{"id": nil}, idFD)
		assert.True(t, ok)
		assert.Nil(t, sub)
	})
	t.Run("hit by proto snake_case name", func(t *testing.T) {
		t.Parallel()
		sub, ok := lookupKey(jsonKeyNode{"tls_client_key": nil}, tlsClientKeyFD)
		assert.True(t, ok)
		assert.Nil(t, sub)
	})
	t.Run("miss", func(t *testing.T) {
		t.Parallel()
		sub, ok := lookupKey(jsonKeyNode{"other": nil}, idFD)
		assert.False(t, ok)
		assert.Nil(t, sub)
	})
}

// TestScrubSensitive_NilAndInvalid covers the early-return paths in the
// scrub walker. Without these, ScrubSensitive's nil-guard and
// scrubMessage's IsValid-guard go untested — both would surface as nil
// dereference panics in production if a future caller passed a zero-value
// message in a hot path.
func TestScrubSensitive_NilAndInvalid(t *testing.T) {
	t.Parallel()

	// nil proto.Message — must not panic.
	ScrubSensitive(nil)

	// Empty / unset sub-message: ProtoReflect on a nil-typed pointer
	// produces an invalid Message. scrubMessage must skip it cleanly.
	var route *configpb.Route // typed nil
	ScrubSensitive(route)

	// Same shape for the sensitive-fields collector.
	assert.Nil(t, SensitiveFieldsSet(nil))
	assert.Nil(t, SensitiveFieldsSet(route))
}
