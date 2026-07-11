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
