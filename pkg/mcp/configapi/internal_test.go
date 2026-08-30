package configapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

// TestParseConnectError_AllCodes round-trips every documented connect.Code
// through parseConnectError to ensure the wire body the inner Connect
// handler emits is decoded into the right typed *connect.Error. Code
// parsing delegates to connect.Code.UnmarshalText, so this test also
// pins our reliance on that contract.
func TestParseConnectError_AllCodes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		wire     string
		wantCode connect.Code
		wantWire bool // expect a typed *connect.Error
	}{
		{"canceled", connect.CodeCanceled, true},
		{"unknown", connect.CodeUnknown, true},
		{"invalid_argument", connect.CodeInvalidArgument, true},
		{"deadline_exceeded", connect.CodeDeadlineExceeded, true},
		{"not_found", connect.CodeNotFound, true},
		{"already_exists", connect.CodeAlreadyExists, true},
		{"permission_denied", connect.CodePermissionDenied, true},
		{"resource_exhausted", connect.CodeResourceExhausted, true},
		{"failed_precondition", connect.CodeFailedPrecondition, true},
		{"aborted", connect.CodeAborted, true},
		{"out_of_range", connect.CodeOutOfRange, true},
		{"unimplemented", connect.CodeUnimplemented, true},
		{"internal", connect.CodeInternal, true},
		{"unavailable", connect.CodeUnavailable, true},
		{"data_loss", connect.CodeDataLoss, true},
		{"unauthenticated", connect.CodeUnauthenticated, true},
		// Unrecognised wire codes fall back to a plain HTTP error; the
		// caller still gets a non-nil error but errors.As fails. Surfacing
		// the unknown name (rather than silently downgrading to a typed
		// CodeUnknown) avoids accidental ErrorMapper matches against the
		// wrong code class.
		{"???", 0, false},
		{"NOTFOUND", 0, false}, // wire is case-sensitive lower_snake_case
	}
	for _, tc := range cases {
		name := tc.wire
		if name == "" {
			name = "<empty>"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body := []byte(`{"code":"` + tc.wire + `","message":"x"}`)
			err := parseConnectError(503, body)
			require.Error(t, err)
			var ce *connect.Error
			gotWire := errors.As(err, &ce)
			require.Equal(t, tc.wantWire, gotWire, "errors.As should be %v", tc.wantWire)
			if gotWire {
				assert.Equal(t, tc.wantCode, ce.Code())
				assert.True(t, connect.IsWireError(err),
					"server-originated errors should be marked as wire errors")
			}
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

func TestRestoreRedactedRouteUpstreams(t *testing.T) {
	password := "https://alice:password-secret@one.example.com/path?q=1"
	token := "https://token-secret@two.example.com/other?q=2"
	maskedPassword := "https://xxxxx@one.example.com/path?q=1"
	maskedToken := "https://xxxxx@two.example.com/other?q=2"

	tests := []struct {
		name     string
		original []string
		incoming []string
		want     []string
		wantErr  bool
	}{
		{name: "unchanged round trip", original: []string{password, token}, incoming: []string{maskedPassword, maskedToken}, want: []string{password, token}},
		{name: "host edit", original: []string{password}, incoming: []string{"https://xxxxx@edited.example.com/path?q=1"}, wantErr: true},
		{name: "scheme edit", original: []string{password}, incoming: []string{"http://xxxxx@one.example.com/path?q=1"}, wantErr: true},
		{name: "path edit", original: []string{password}, incoming: []string{"https://xxxxx@one.example.com/edited?q=1"}, wantErr: true},
		{name: "query edit", original: []string{password}, incoming: []string{"https://xxxxx@one.example.com/path?q=edited"}, wantErr: true},
		{name: "reordered", original: []string{password, token}, incoming: []string{maskedToken, maskedPassword}, wantErr: true},
		{name: "insert shifts masked entries", original: []string{password, token}, incoming: []string{"https://new.example.com", maskedPassword, maskedToken}, wantErr: true},
		{name: "delete shifts masked entries", original: []string{password, token}, incoming: []string{maskedToken}, wantErr: true},
		{name: "no original entry for redacted placeholder", original: nil, incoming: []string{"https://xxxxx@one.example.com/path"}, wantErr: true},
		{
			name: "duplicate presentations stay index bound",
			original: []string{
				"https://first-secret@same.example.com/path",
				"https://second-secret@same.example.com/path",
			},
			incoming: []string{
				"https://xxxxx@same.example.com/path",
				"https://xxxxx@same.example.com/path",
			},
			want: []string{
				"https://first-secret@same.example.com/path",
				"https://second-secret@same.example.com/path",
			},
		},
		{name: "explicit no userinfo removes credentials", original: []string{password}, incoming: []string{"https://one.example.com/path?q=1"}, want: []string{"https://one.example.com/path?q=1"}},
		{name: "explicit credentials replace", original: []string{password}, incoming: []string{"https://bob:new-secret@one.example.com/path?q=1"}, want: []string{"https://bob:new-secret@one.example.com/path?q=1"}},
		{name: "literal xxxxx with no hidden original stays explicit", original: []string{"https://one.example.com/path"}, incoming: []string{"https://xxxxx@one.example.com/path"}, want: []string{"https://xxxxx@one.example.com/path"}},
		{name: "xxxxx password form disambiguates replacement", original: []string{password}, incoming: []string{"https://xxxxx:@one.example.com/path?q=1"}, want: []string{"https://xxxxx:@one.example.com/path?q=1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalBefore := append([]string(nil), tt.original...)
			incomingBefore := append([]string(nil), tt.incoming...)
			got, err := RestoreRedactedRouteUpstreams(tt.original, tt.incoming)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
			assert.Equal(t, originalBefore, tt.original, "original runtime values must not be mutated")
			assert.Equal(t, incomingBefore, tt.incoming, "incoming presentation values must not be mutated")
		})
	}

	t.Run("unmatched index is named in the error", func(t *testing.T) {
		_, err := RestoreRedactedRouteUpstreams(nil, []string{"https://xxxxx@one.example.com/path"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unmatched redacted route upstream at index 0")
	})
}

func TestRestoreRedactedRouteUpstreamsErrorsDoNotEchoInput(t *testing.T) {
	const incomingCanary = "INCOMING_PARSE_SECRET_CANARY"
	_, err := RestoreRedactedRouteUpstreams(nil, []string{"https://xxxxx:" + incomingCanary + "@[::1"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), incomingCanary)

	const existingCanary = "EXISTING_PARSE_SECRET_CANARY"
	_, err = RestoreRedactedRouteUpstreams(
		[]string{"https://user:" + existingCanary + "@[::1"},
		[]string{"https://xxxxx@one.example.com"},
	)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), existingCanary)

	const mismatchExistingCanary = "MISMATCH_EXISTING_SECRET_CANARY"
	const mismatchIncomingCanary = "MISMATCH_INCOMING_HOST_CANARY"
	_, err = RestoreRedactedRouteUpstreams(
		[]string{"https://user:" + mismatchExistingCanary + "@one.example.com"},
		[]string{"https://xxxxx@" + mismatchIncomingCanary + ".example.com"},
	)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), mismatchExistingCanary)
	assert.NotContains(t, err.Error(), mismatchIncomingCanary)
}

func TestScrubSensitiveRouteUpstreamsAcrossDescriptors(t *testing.T) {
	t.Run("core route", func(t *testing.T) {
		route := &configpb.Route{To: []string{
			"https://user:password-canary@one.example.com",
			"https://token-canary@two.example.com",
		}}
		assert.Contains(t, SensitiveFieldsSet(route), "to[]")
		ScrubSensitive(route)
		assert.Equal(t, []string{
			"https://xxxxx@one.example.com",
			"https://xxxxx@two.example.com",
		}, route.GetTo())
	})

	t.Run("dashboard route", func(t *testing.T) {
		file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
			Syntax:  new("proto3"),
			Name:    new("dashboard_route_test.proto"),
			Package: new("pomerium.dashboard"),
			MessageType: []*descriptorpb.DescriptorProto{{
				Name: new("Route"),
				Field: []*descriptorpb.FieldDescriptorProto{{
					Name:   new("to"),
					Number: proto.Int32(1),
					Label:  descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
					Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
				}},
			}},
		}, nil)
		require.NoError(t, err)
		route := dynamicpb.NewMessage(file.Messages().ByName("Route"))
		toField := route.Descriptor().Fields().ByName("to")
		to := route.Mutable(toField).List()
		to.Append(protoreflect.ValueOfString("https://dashboard-token-canary@dashboard.example.com/path?q=1"))

		assert.Contains(t, SensitiveFieldsSet(route), "to[]")
		ScrubSensitive(route)
		assert.Equal(t, "https://xxxxx@dashboard.example.com/path?q=1", route.Get(toField).List().Get(0).String())
	})
}

func TestSensitiveAnyTraversal(t *testing.T) {
	const canary = "NESTED_ANY_IDP_CLIENT_SECRET_CANARY"

	tests := []struct {
		name     string
		newMsg   func(*anypb.Any) proto.Message
		wantPath string
	}{
		{
			name:     "direct",
			newMsg:   func(a *anypb.Any) proto.Message { return a },
			wantPath: "routes[].idpClientSecret",
		},
		{
			name: "map",
			newMsg: func(a *anypb.Any) proto.Message {
				return &registrypb.RegisterRequest{Metadata: map[string]*anypb.Any{"config": a}}
			},
			wantPath: "metadata[].routes[].idpClientSecret",
		},
		{
			name: "list",
			newMsg: func(a *anypb.Any) proto.Message {
				return &statuspb.Status{Details: []*anypb.Any{a}}
			},
			wantPath: "details[].routes[].idpClientSecret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := tt.newMsg(mustSensitiveConfigAny(t, canary))
			second := tt.newMsg(mustSensitiveConfigAny(t, canary))

			assert.Contains(t, SensitiveFieldsSet(first), tt.wantPath)
			ScrubSensitive(first)
			ScrubSensitive(second)

			firstJSON, err := protojson.Marshal(first)
			require.NoError(t, err)
			assert.NotContains(t, string(firstJSON), canary)
			firstWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(first)
			require.NoError(t, err)
			secondWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(second)
			require.NoError(t, err)
			assert.Equal(t, firstWire, secondWire, "Any payload repacking must be deterministic")
		})
	}
}

func TestScrubSensitiveAnyFailsClosedAtBounds(t *testing.T) {
	tests := []struct {
		name string
		msg  *anypb.Any
	}{
		{
			name: "unknown type",
			msg: &anypb.Any{
				TypeUrl: "type.googleapis.com/unknown.Secret",
				Value:   []byte("UNKNOWN_ANY_SECRET_CANARY"),
			},
		},
		{
			name: "malformed payload",
			msg: &anypb.Any{
				TypeUrl: mustSensitiveConfigAny(t, "").TypeUrl,
				Value:   []byte{0xff},
			},
		},
		{
			name: "oversized payload",
			msg: &anypb.Any{
				TypeUrl: mustSensitiveConfigAny(t, "").TypeUrl,
				Value:   bytes.Repeat([]byte{'x'}, maxSensitiveAnyBytes+1),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, []string{"value"}, SensitiveFieldsSet(tt.msg))
			ScrubSensitive(tt.msg)
			assert.Empty(t, tt.msg.Value)
		})
	}
}

func TestScrubSensitiveAnyFailsClosedBeyondDepthBound(t *testing.T) {
	const canary = "OVER_DEPTH_ANY_IDP_CLIENT_SECRET_CANARY"
	var msg proto.Message = sensitiveConfig(canary)
	for range maxSensitiveAnyDepth + 1 {
		var err error
		msg, err = anypb.New(msg)
		require.NoError(t, err)
	}
	outer := msg.(*anypb.Any)

	assert.Equal(t, []string{"value"}, SensitiveFieldsSet(outer))
	ScrubSensitive(outer)
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(outer)
	require.NoError(t, err)
	assert.NotContains(t, string(wire), canary)
}

func TestSensitiveFieldsSetReportsClearedNestedAny(t *testing.T) {
	msg := &statuspb.Status{Details: []*anypb.Any{{
		TypeUrl: "type.googleapis.com/unknown.Secret",
		Value:   []byte("UNKNOWN_ANY_SECRET_CANARY"),
	}}}

	redacted := SensitiveFieldsSet(msg)
	assert.Equal(t, []string{"details[].value"}, redacted)
	ScrubSensitive(msg)
	assert.Empty(t, msg.GetDetails()[0].GetValue())
	assert.Equal(t, []string{"details[].value"}, buildMeta(nil, nil, msg, redacted, nil)["scrubbedFields"])
}

func TestScrubSensitiveAnyEnforcesCumulativeByteBound(t *testing.T) {
	largeName := strings.Repeat("x", maxSensitiveAnyBytes/2+1)
	newLargeAny := func(password string) *anypb.Any {
		cfg := sensitiveConfig(password)
		cfg.Routes[0].Name = &largeName
		return mustSensitiveConfigAnyFromMessage(t, cfg)
	}
	msg := &statuspb.Status{Details: []*anypb.Any{
		newLargeAny("FIRST_ANY_PASSWORD_CANARY"),
		newLargeAny("SECOND_ANY_PASSWORD_CANARY"),
	}}

	ScrubSensitive(msg)
	require.NotEmpty(t, msg.Details[0].Value)
	assert.Empty(t, msg.Details[1].Value, "aggregate Any input beyond the byte budget must fail closed")
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	require.NoError(t, err)
	assert.NotContains(t, string(wire), "FIRST_ANY_PASSWORD_CANARY")
	assert.NotContains(t, string(wire), "SECOND_ANY_PASSWORD_CANARY")
}

func TestScrubSensitiveDropsUnknownWireFields(t *testing.T) {
	tests := []struct {
		name      string
		newMsg    func(string) proto.Message
		unknownAt func(proto.Message) protoreflect.Message
	}{
		{
			name:   "root",
			newMsg: func(string) proto.Message { return sensitiveConfig("") },
			unknownAt: func(msg proto.Message) protoreflect.Message {
				return msg.ProtoReflect()
			},
		},
		{
			name:   "nested",
			newMsg: func(string) proto.Message { return sensitiveConfig("") },
			unknownAt: func(msg proto.Message) protoreflect.Message {
				return msg.(*configpb.Config).Routes[0].ProtoReflect()
			},
		},
		{
			name: "Any payload",
			newMsg: func(canary string) proto.Message {
				cfg := sensitiveConfig("")
				cfg.ProtoReflect().SetUnknown(sensitiveUnknownWire(canary))
				return mustSensitiveConfigAnyFromMessage(t, cfg)
			},
			unknownAt: func(msg proto.Message) protoreflect.Message {
				var cfg configpb.Config
				require.NoError(t, msg.(*anypb.Any).UnmarshalTo(&cfg))
				return cfg.ProtoReflect()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canary := "UNKNOWN_WIRE_SECRET_CANARY_" + tt.name
			first := tt.newMsg(canary)
			second := tt.newMsg(canary)
			if tt.name != "Any payload" {
				tt.unknownAt(first).SetUnknown(sensitiveUnknownWire(canary))
				tt.unknownAt(second).SetUnknown(sensitiveUnknownWire(canary))
			}

			assert.Empty(t, SensitiveFieldsSet(first), "unknown fields cannot produce a trustworthy redaction path")
			ScrubSensitive(first)
			ScrubSensitive(second)

			assert.Empty(t, tt.unknownAt(first).GetUnknown())
			firstWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(first)
			require.NoError(t, err)
			secondWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(second)
			require.NoError(t, err)
			assert.Equal(t, firstWire, secondWire)
			assert.NotContains(t, string(firstWire), canary)
		})
	}
}

func mustSensitiveConfigAny(t testing.TB, password string) *anypb.Any {
	t.Helper()
	return mustSensitiveConfigAnyFromMessage(t, sensitiveConfig(password))
}

func mustSensitiveConfigAnyFromMessage(t testing.TB, msg proto.Message) *anypb.Any {
	t.Helper()
	a, err := anypb.New(msg)
	require.NoError(t, err)
	return a
}

func sensitiveConfig(secret string) *configpb.Config {
	route := &configpb.Route{}
	if secret != "" {
		route.IdpClientSecret = &secret
	}
	return &configpb.Config{Routes: []*configpb.Route{route}}
}

func sensitiveUnknownWire(value string) []byte {
	wire := protowire.AppendTag(nil, 65000, protowire.BytesType)
	return protowire.AppendBytes(wire, []byte(value))
}

// TestParseConnectError_PreservesCodeWhenMessageEmpty locks the contract
// that a wire body carrying a recognised Connect code with an empty
// message still produces a typed *connect.Error: keying on wire.Code
// (not wire.Message) keeps ErrorMappers able to match by Code() even
// when the upstream service emits no message text.
func TestParseConnectError_PreservesCodeWhenMessageEmpty(t *testing.T) {
	t.Parallel()

	body := []byte(`{"code":"unauthenticated","message":""}`)
	err := parseConnectError(http.StatusUnauthorized, body)
	require.Error(t, err)

	var ce *connect.Error
	require.True(t, errors.As(err, &ce),
		"parseConnectError must return a typed *connect.Error when wire.Code is set")
	assert.Equal(t, connect.CodeUnauthenticated, ce.Code())
}

// TestScrubSensitiveAnyAtExactDepthBound pins the passing side of the Any
// nesting bound: exactly maxSensitiveAnyDepth layers still unpacks, scrubs,
// and repacks every layer in place. TestScrubSensitiveAnyFailsClosedBeyondDepthBound
// pins the failing side one layer deeper.
func TestScrubSensitiveAnyAtExactDepthBound(t *testing.T) {
	const canary = "DEPTH_BOUND_CANARY"
	var msg proto.Message = sensitiveConfig(canary)
	for range maxSensitiveAnyDepth {
		var err error
		msg, err = anypb.New(msg)
		require.NoError(t, err)
	}
	outer := msg.(*anypb.Any)

	ScrubSensitive(outer)

	layer := outer
	for i := range maxSensitiveAnyDepth - 1 {
		require.NotEmptyf(t, layer.GetValue(), "layer %d must be scrubbed in place, not wholesale-cleared", i)
		var next anypb.Any
		require.NoError(t, layer.UnmarshalTo(&next))
		layer = &next
	}
	require.NotEmpty(t, layer.GetValue())
	var cfg configpb.Config
	require.NoError(t, layer.UnmarshalTo(&cfg))
	assert.Empty(t, cfg.GetRoutes()[0].GetIdpClientSecret())
}

// TestScrubSensitiveAnyAtExactByteBound pins the passing side of the
// cumulative Any byte budget: a Value exactly maxSensitiveAnyBytes long is
// still unpacked, scrubbed, and repacked, since unpackAny's budget check is
// a strict ">" and only fails closed once the input exceeds the bound.
func TestScrubSensitiveAnyAtExactByteBound(t *testing.T) {
	const canary = "BYTE_BOUND_CANARY"
	cfgBytes, err := proto.Marshal(sensitiveConfig(canary))
	require.NoError(t, err)

	const unknownField protowire.Number = 65000
	tagSize := protowire.SizeTag(unknownField)
	remaining := maxSensitiveAnyBytes - len(cfgBytes) - tagSize

	// SizeBytes(n) = SizeVarint(n) + n is a step function of n, so solve for
	// the payload length whose own varint-size is self-consistent with the
	// remaining budget.
	var payloadLen int
	found := false
	for varintSize := 1; varintSize <= 10; varintSize++ {
		n := remaining - varintSize
		if n >= 0 && protowire.SizeVarint(uint64(n)) == varintSize {
			payloadLen = n
			found = true
			break
		}
	}
	require.True(t, found, "could not compute an exact padding length")

	wire := protowire.AppendTag(append([]byte(nil), cfgBytes...), unknownField, protowire.BytesType)
	wire = protowire.AppendBytes(wire, bytes.Repeat([]byte{'p'}, payloadLen))
	require.Len(t, wire, maxSensitiveAnyBytes)

	a := &anypb.Any{
		TypeUrl: mustSensitiveConfigAny(t, "").TypeUrl,
		Value:   wire,
	}

	ScrubSensitive(a)

	assert.NotEmpty(t, a.Value)
	assert.Less(t, len(a.Value), maxSensitiveAnyBytes, "discarding the unknown padding field must shrink the repacked value")
	assert.NotContains(t, string(a.Value), canary)
}

// TestScrubSensitiveMapBudgetIsDeterministicAcrossWalkers pins that
// SensitiveFieldsSet and ScrubSensitive, run in production order over the
// same map, spend their independent byte budgets identically. Map iteration
// order is otherwise undefined, so without rangeMessageMap's key sort the two
// walks could fail closed on different entries and scrubbedFields metadata
// would misreport what ScrubSensitive actually cleared.
func TestScrubSensitiveMapBudgetIsDeterministicAcrossWalkers(t *testing.T) {
	largeName := strings.Repeat("x", maxSensitiveAnyBytes/2+1)
	newLargeAny := func(password string) *anypb.Any {
		cfg := sensitiveConfig(password)
		cfg.Routes[0].Name = &largeName
		return mustSensitiveConfigAnyFromMessage(t, cfg)
	}
	build := func() *registrypb.RegisterRequest {
		return &registrypb.RegisterRequest{Metadata: map[string]*anypb.Any{
			"a": newLargeAny("MAP_BUDGET_A_CANARY"),
			"b": newLargeAny("MAP_BUDGET_B_CANARY"),
		}}
	}

	first := build()
	paths := SensitiveFieldsSet(first)
	assert.Contains(t, paths, "metadata[].value", "sorted key order charges \"b\" second, so it fails closed and reports as opaque")
	ScrubSensitive(first)

	require.NotEmpty(t, first.Metadata["a"].Value, "sorted key order charges \"a\" first")
	assert.Empty(t, first.Metadata["b"].Value, "\"b\" exhausts the shared budget after \"a\"")

	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(first)
	require.NoError(t, err)
	assert.NotContains(t, string(wire), "MAP_BUDGET_A_CANARY")
	assert.NotContains(t, string(wire), "MAP_BUDGET_B_CANARY")

	second := build()
	ScrubSensitive(second)
	secondWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(second)
	require.NoError(t, err)
	assert.Equal(t, wire, secondWire, "the budget walk must be deterministic across separately-built instances")
}

// TestScrubSensitiveEmptyAnyIsNoOp pins that an Any with a TypeUrl but no
// Value (m.Has(valueField) is false for an empty byte string) is treated as
// "nothing embedded" rather than a decode failure: unpackAny returns ok=true
// with a nil embedded message, so neither field is touched.
func TestScrubSensitiveEmptyAnyIsNoOp(t *testing.T) {
	typeURL := mustSensitiveConfigAny(t, "").TypeUrl
	a := &anypb.Any{TypeUrl: typeURL}

	assert.Nil(t, SensitiveFieldsSet(a))
	ScrubSensitive(a)
	assert.Equal(t, typeURL, a.TypeUrl)
	assert.Empty(t, a.Value)
}

// TestScrubSensitiveAnyMissingTypeURLFailsClosed pins that an Any carrying a
// Value but no TypeUrl fails closed: with no type to resolve, the payload
// cannot be classified, so ScrubSensitive clears it and SensitiveFieldsSet
// reports it as a redacted "value" path rather than passing it through.
func TestScrubSensitiveAnyMissingTypeURLFailsClosed(t *testing.T) {
	a := &anypb.Any{Value: []byte("NO_TYPE_URL_SECRET_CANARY")}

	assert.Equal(t, []string{"value"}, SensitiveFieldsSet(a))
	ScrubSensitive(a)
	assert.Empty(t, a.Value)
}

// TestScrubSensitiveInvalidRouteUpstream pins that an unparseable "to" entry
// is reported as sensitive (it may be hiding credentials the parser could
// not recover) and is replaced with a fixed placeholder rather than echoed
// back verbatim.
func TestScrubSensitiveInvalidRouteUpstream(t *testing.T) {
	const canary = "invalid-canary"
	route := &configpb.Route{To: []string{"https://user:" + canary + "@[::1"}}

	assert.Contains(t, SensitiveFieldsSet(route), "to[]")
	ScrubSensitive(route)
	require.Len(t, route.GetTo(), 1)
	assert.Equal(t, "invalid upstream URL", route.GetTo()[0])
}

// TestRangeMessageMapKeyKindOrdering directly pins rangeMessageMap's sort
// order for the three integer-ish map key kinds it special-cases: bool
// (false before true), signed (ascending, including negatives), and
// unsigned (ascending). ScrubSensitive and SensitiveFieldsSet only exercise
// this through string- and message-keyed config maps; this covers the
// dynamic-descriptor path for the others directly.
func TestRangeMessageMapKeyKindOrdering(t *testing.T) {
	const pkg = "pomerium.configapi.maptest"
	mapEntry := func(name string, keyType descriptorpb.FieldDescriptorProto_Type) *descriptorpb.DescriptorProto {
		return &descriptorpb.DescriptorProto{
			Name: new(name),
			Field: []*descriptorpb.FieldDescriptorProto{
				{
					Name:   new("key"),
					Number: proto.Int32(1),
					Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					Type:   keyType.Enum(),
				},
				{
					Name:     new("value"),
					Number:   proto.Int32(2),
					Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
					TypeName: new("." + pkg + ".Container.Inner"),
				},
			},
			Options: &descriptorpb.MessageOptions{MapEntry: new(true)},
		}
	}

	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Syntax:  new("proto3"),
		Name:    new("range_message_map_test.proto"),
		Package: new(pkg),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("Container"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{
					Name:     new("bool_map"),
					Number:   proto.Int32(1),
					Label:    descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
					Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
					TypeName: new("." + pkg + ".Container.BoolMapEntry"),
				},
				{
					Name:     new("int64_map"),
					Number:   proto.Int32(2),
					Label:    descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
					Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
					TypeName: new("." + pkg + ".Container.Int64MapEntry"),
				},
				{
					Name:     new("uint64_map"),
					Number:   proto.Int32(3),
					Label:    descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
					Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
					TypeName: new("." + pkg + ".Container.Uint64MapEntry"),
				},
			},
			NestedType: []*descriptorpb.DescriptorProto{
				{
					Name: new("Inner"),
					Field: []*descriptorpb.FieldDescriptorProto{{
						Name:   new("tag"),
						Number: proto.Int32(1),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
					}},
				},
				mapEntry("BoolMapEntry", descriptorpb.FieldDescriptorProto_TYPE_BOOL),
				mapEntry("Int64MapEntry", descriptorpb.FieldDescriptorProto_TYPE_INT64),
				mapEntry("Uint64MapEntry", descriptorpb.FieldDescriptorProto_TYPE_UINT64),
			},
		}},
	}, nil)
	require.NoError(t, err)

	containerDesc := file.Messages().ByName("Container")
	innerDesc := containerDesc.Messages().ByName("Inner")
	tagField := innerDesc.Fields().ByName("tag")
	container := dynamicpb.NewMessage(containerDesc)
	fields := container.Descriptor().Fields()

	setEntry := func(fieldName string, key protoreflect.Value, tag string) {
		fd := fields.ByName(protoreflect.Name(fieldName))
		inner := dynamicpb.NewMessage(innerDesc)
		inner.Set(tagField, protoreflect.ValueOfString(tag))
		container.Mutable(fd).Map().Set(key.MapKey(), protoreflect.ValueOfMessage(inner))
	}

	// Insert out of sorted order so a passing test can only be explained by
	// rangeMessageMap doing the sorting, not incidental map iteration order.
	setEntry("bool_map", protoreflect.ValueOfBool(true), "true")
	setEntry("bool_map", protoreflect.ValueOfBool(false), "false")
	setEntry("int64_map", protoreflect.ValueOfInt64(5), "5")
	setEntry("int64_map", protoreflect.ValueOfInt64(-3), "-3")
	setEntry("int64_map", protoreflect.ValueOfInt64(0), "0")
	setEntry("uint64_map", protoreflect.ValueOfUint64(42), "42")
	setEntry("uint64_map", protoreflect.ValueOfUint64(1), "1")
	setEntry("uint64_map", protoreflect.ValueOfUint64(1000), "1000")

	visit := func(fieldName string) []string {
		fd := fields.ByName(protoreflect.Name(fieldName))
		var order []string
		rangeMessageMap(container.Get(fd).Map(), fd.MapKey().Kind(), func(_ protoreflect.MapKey, v protoreflect.Value) {
			order = append(order, v.Message().Get(tagField).String())
		})
		return order
	}

	assert.Equal(t, []string{"false", "true"}, visit("bool_map"))
	assert.Equal(t, []string{"-3", "0", "5"}, visit("int64_map"))
	assert.Equal(t, []string{"1", "42", "1000"}, visit("uint64_map"))
}

// TestScrubSensitiveAnyOverUnmarshalRecursionLimitFailsClosed pins that a
// plain (non-Any) message nested far beyond proto's default unmarshal
// recursion limit fails closed rather than panicking. Plain-message
// recursion has no depth counter of its own in scrubMessage; proto's
// unmarshal recursion limit is the guard that actually bites here, since
// unpackAny re-decodes the embedded bytes with DiscardUnknown rather than
// walking the already-parsed message.
func TestScrubSensitiveAnyOverUnmarshalRecursionLimitFailsClosed(t *testing.T) {
	inner := &structpb.Struct{Fields: map[string]*structpb.Value{"k": structpb.NewNumberValue(1)}}
	for range 10000 {
		inner = &structpb.Struct{Fields: map[string]*structpb.Value{"k": structpb.NewStructValue(inner)}}
	}

	a, err := anypb.New(inner)
	require.NoError(t, err)

	ScrubSensitive(a)
	assert.Empty(t, a.Value)
}

// TestScrubSensitiveSkipsScalarMaps pins that a scalar-valued map (string ->
// string, not message-valued) is left alone by both walkers: fd.MapValue().Kind()
// is not MessageKind, so it can never carry a nested sensitive field, and
// scrubMessage's map branch explicitly skips it rather than trying to
// recurse into a non-message value.
func TestScrubSensitiveSkipsScalarMaps(t *testing.T) {
	secret := "SCALAR_MAP_CANARY"
	route := &configpb.Route{
		IdpClientSecret:   &secret,
		SetRequestHeaders: map[string]string{"X-Foo": "bar"},
	}

	assert.Equal(t, []string{"idpClientSecret"}, SensitiveFieldsSet(route))

	ScrubSensitive(route)
	assert.Empty(t, route.GetIdpClientSecret())
	assert.Equal(t, map[string]string{"X-Foo": "bar"}, route.GetSetRequestHeaders())
}

// TestScrubSensitiveRouteMessageWithMalformedToField pins the defensive
// guard shared by scrubConfigRouteUpstreams and collectRouteUpstreamSensitive:
// isRouteMessage matches pomerium.config.Route/pomerium.dashboard.Route by
// name only, so a hand-built or version-skewed descriptor that carries that
// name but whose "to" field isn't a repeated string must be left alone
// rather than assumed safe to redact.
func TestScrubSensitiveRouteMessageWithMalformedToField(t *testing.T) {
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Syntax:  new("proto3"),
		Name:    new("malformed_dashboard_route_test.proto"),
		Package: new("pomerium.dashboard"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: new("Route"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name:   new("to"),
				Number: proto.Int32(1),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), // singular, not repeated
				Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			}},
		}},
	}, nil)
	require.NoError(t, err)
	route := dynamicpb.NewMessage(file.Messages().ByName("Route"))
	toField := route.Descriptor().Fields().ByName("to")
	const canary = "https://user:MALFORMED_TO_FIELD_CANARY@example.com"
	route.Set(toField, protoreflect.ValueOfString(canary))

	assert.Nil(t, SensitiveFieldsSet(route))
	ScrubSensitive(route)
	assert.Equal(t, canary, route.Get(toField).String())
}
