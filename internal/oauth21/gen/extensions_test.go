package gen_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/identity/identity"
)

var _ identity.State = (*oauth21.IDPSession)(nil)

func TestIDPSessionSetRawIDToken(t *testing.T) {
	t.Parallel()

	s := &oauth21.IDPSession{}
	s.SetRawIDToken("first")
	assert.Equal(t, "first", s.GetRawIdToken())

	s.SetRawIDToken("second")
	assert.Equal(t, "second", s.GetRawIdToken())

	s.SetRawIDToken("")
	assert.Empty(t, s.GetRawIdToken())

	var nilSession *oauth21.IDPSession
	assert.NotPanics(t, func() { nilSession.SetRawIDToken("x") })
}

func TestIDPSessionUnmarshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("set", func(t *testing.T) {
		t.Parallel()

		s := &oauth21.IDPSession{}
		require.NoError(t, json.Unmarshal([]byte(`{"sub":"user-1","groups":["a","b"]}`), s))
		assert.Equal(t, map[string]any{
			"sub":    []any{"user-1"},
			"groups": []any{"a", "b"},
		}, s.GetClaims().AsMap())
	})

	t.Run("merge", func(t *testing.T) {
		t.Parallel()

		s := &oauth21.IDPSession{Claims: mustStruct(t, map[string]any{
			"sub":   []any{"user-1"},
			"email": []any{"old@example.com"},
		})}
		require.NoError(t, json.Unmarshal([]byte(`{"email":"new@example.com","name":"Alice"}`), s))
		assert.Equal(t, map[string]any{
			"sub":   []any{"user-1"},
			"email": []any{"new@example.com"},
			"name":  []any{"Alice"},
		}, s.GetClaims().AsMap())
	})

	t.Run("nested", func(t *testing.T) {
		t.Parallel()

		s := &oauth21.IDPSession{}
		require.NoError(t, json.Unmarshal([]byte(`{"exp":1700000000,"meta":{"a":{"b":true}},"none":null}`), s))
		assert.Equal(t, map[string]any{
			"exp":      []any{float64(1700000000)},
			"meta.a.b": []any{true},
			"none":     []any{nil},
		}, s.GetClaims().AsMap())
	})

	t.Run("nested_merge", func(t *testing.T) {
		t.Parallel()

		s := &oauth21.IDPSession{}
		require.NoError(t, json.Unmarshal([]byte(`{"meta":{"a":1}}`), s))
		require.NoError(t, json.Unmarshal([]byte(`{"meta":{"b":2}}`), s))
		assert.Equal(t, map[string]any{
			"meta.a": []any{float64(1)},
			"meta.b": []any{float64(2)},
		}, s.GetClaims().AsMap())
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		s := &oauth21.IDPSession{Claims: mustStruct(t, map[string]any{"sub": []any{"user-1"}})}
		require.NoError(t, json.Unmarshal([]byte(`{}`), s))
		assert.Equal(t, map[string]any{"sub": []any{"user-1"}}, s.GetClaims().AsMap())
	})

	t.Run("invalid_json", func(t *testing.T) {
		t.Parallel()

		s := &oauth21.IDPSession{}
		assert.Error(t, json.Unmarshal([]byte(`not json`), s))
		assert.Nil(t, s.GetClaims())
	})

	t.Run("other_fields", func(t *testing.T) {
		t.Parallel()

		s := &oauth21.IDPSession{Id: "session-1", RawIdToken: "raw"}
		require.NoError(t, json.Unmarshal([]byte(`{"sub":"user-1"}`), s))
		assert.Equal(t, "session-1", s.GetId())
		assert.Equal(t, "raw", s.GetRawIdToken())
	})
}

func TestIDPSessionMarshalJSON(t *testing.T) {
	t.Parallel()

	s := &oauth21.IDPSession{
		Id:     "session-1",
		Claims: mustStruct(t, map[string]any{"sub": []any{"user-1"}, "groups": []any{"a", "b"}}),
	}
	data, err := json.Marshal(s)
	require.NoError(t, err)
	assert.JSONEq(t, `{"sub":["user-1"],"groups":["a","b"]}`, string(data))

	roundTripped := &oauth21.IDPSession{}
	require.NoError(t, json.Unmarshal(data, roundTripped))
	assert.Equal(t, s.GetClaims().AsMap(), roundTripped.GetClaims().AsMap())

	empty, err := json.Marshal(&oauth21.IDPSession{})
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(empty))
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}
