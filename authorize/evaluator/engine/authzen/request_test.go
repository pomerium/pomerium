package authzen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

func TestBuildSubject(t *testing.T) {
	t.Parallel()

	cfg := Config{SubjectType: DefaultSubjectType}

	t.Run("authenticated user", func(t *testing.T) {
		t.Parallel()
		s := buildSubject(&evaluator.Request{
			Policy:  newPolicy(t),
			Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
		}, cfg)
		assert.Equal(t, DefaultSubjectType, s.Type)
		assert.Equal(t, "u1", s.ID)
		assert.Equal(t, "s1", s.Properties["session_id"])
		assert.Equal(t, "https://from.example.com", s.Properties["route_from"])
	})

	t.Run("anonymous user", func(t *testing.T) {
		t.Parallel()
		s := buildSubject(&evaluator.Request{Policy: newPolicy(t)}, cfg)
		assert.Equal(t, anonymousSubjectID, s.ID)
		_, hasSession := s.Properties["session_id"]
		assert.False(t, hasSession)
	})
}

func TestBuildResource(t *testing.T) {
	t.Parallel()

	cfg := Config{ResourceType: DefaultResourceType}

	t.Run("populates HTTP attributes", func(t *testing.T) {
		t.Parallel()
		policy := newPolicy(t)
		wantID, err := policy.RouteID()
		require.NoError(t, err)

		r := buildResource(&evaluator.Request{
			Policy: policy,
			HTTP: evaluator.RequestHTTP{
				Method: "GET",
				Host:   "from.example.com",
				Path:   "/x",
				IP:     "1.2.3.4",
			},
		}, cfg)
		assert.Equal(t, DefaultResourceType, r.Type)
		assert.Equal(t, wantID, r.ID)
		assert.Equal(t, "from.example.com", r.Properties["host"])
		assert.Equal(t, "/x", r.Properties["path"])
		assert.Equal(t, "GET", r.Properties["method"])
		assert.Equal(t, "1.2.3.4", r.Properties["ip"])
		assert.True(t, r.Properties["client_cert_valid"].(bool))
	})

	t.Run("forwards precomputed client cert validity", func(t *testing.T) {
		t.Parallel()
		invalid := false
		r := buildResource(&evaluator.Request{
			Policy:                     newPolicy(t),
			PrecomputedClientCertValid: &invalid,
		}, cfg)
		assert.False(t, r.Properties["client_cert_valid"].(bool))
	})
}

func TestBuildContext(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when empty", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, buildContext(&evaluator.Request{}))
	})

	t.Run("populates ip", func(t *testing.T) {
		t.Parallel()
		c := buildContext(&evaluator.Request{HTTP: evaluator.RequestHTTP{IP: "1.2.3.4"}})
		assert.Equal(t, "1.2.3.4", c["ip"])
	})
}
