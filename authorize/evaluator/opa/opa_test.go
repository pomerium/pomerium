package opa

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
)

func Test_Eval(t *testing.T) {
	t.Parallel()
	type Identity struct {
		User              string   `json:"user,omitempty"`
		Email             string   `json:"email,omitempty"`
		Groups            []string `json:"groups,omitempty"`
		ImpersonateEmail  string   `json:"impersonate_email,omitempty"`
		ImpersonateGroups []string `json:"impersonate_groups,omitempty"`
	}
	tests := []struct {
		name     string
		policies []config.Policy
		route    string
		Identity *Identity
		admins   []string
		secret   string
		want     bool
	}{
		{"valid domain", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "user@example.com"}, nil, "secret", true},
		{"valid domain with admins", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "user@example.com"}, []string{"admin@example.com"}, "secret", true},
		{"invalid domain prepend", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "a@1example.com"}, nil, "secret", false},
		{"invalid domain postpend", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "user@example.com2"}, nil, "secret", false},
		{"valid group", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"admin"}}}, "from.example", &Identity{Email: "user@example.com", Groups: []string{"admin"}}, nil, "secret", true},
		{"invalid group", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"admin"}}}, "from.example", &Identity{Email: "user@example.com", Groups: []string{"everyone"}}, nil, "secret", false},
		{"invalid empty", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"admin"}}}, "from.example", &Identity{Email: "user@example.com", Groups: []string{""}}, nil, "secret", false},
		{"valid group multiple", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"admin"}}}, "from.example", &Identity{Email: "user@example.com", Groups: []string{"everyone", "admin"}}, nil, "secret", true},
		{"invalid group multiple", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"admin"}}}, "from.example", &Identity{Email: "user@example.com", Groups: []string{"everyones", "sadmin"}}, nil, "secret", false},
		{"valid user email", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedUsers: []string{"user@example.com"}}}, "from.example", &Identity{Email: "user@example.com"}, nil, "secret", true},
		{"invalid user email", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedUsers: []string{"user@example.com"}}}, "from.example", &Identity{Email: "user2@example.com"}, nil, "secret", false},
		{"empty everything", []config.Policy{{From: "https://from.example", To: "https://to.example"}}, "from.example", &Identity{Email: "user2@example.com"}, nil, "secret", false},
		{"empty policy", []config.Policy{}, "from.example", &Identity{Email: "user2@example.com"}, nil, "secret", false},
		// impersonation related
		{"admin not impersonating allowed", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "admin@example.com"}, []string{"admin@example.com"}, "secret", true},
		{"admin not impersonating denied", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "admin@admin-domain.com"}, []string{"admin@admin-domain.com"}, "secret", false},
		{"impersonating match domain", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@example.com"}, []string{"admin@admin-domain.com"}, "secret", true},
		{"impersonating does not match domain", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@not-example.com"}, []string{"admin@admin-domain.com"}, "secret", false},
		{"impersonating match email", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedUsers: []string{"user@example.com"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@example.com"}, []string{"admin@admin-domain.com"}, "secret", true},
		{"impersonating does not match email", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedUsers: []string{"user@example.com"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateEmail: "user@not-example.com"}, []string{"admin@admin-domain.com"}, "secret", false},
		{"impersonating match groups", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"support"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"support"}}, []string{"admin@admin-domain.com"}, "secret", true},
		{"impersonating match many groups", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"support"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"a", "b", "c", "support"}}, []string{"admin@admin-domain.com"}, "secret", true},
		{"impersonating does not match groups", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"support"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"not support"}}, []string{"admin@admin-domain.com"}, "secret", false},
		{"impersonating does not match many groups", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"support"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{"not support", "b", "c"}}, []string{"admin@admin-domain.com"}, "secret", false},
		{"impersonating does not match empty groups", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedGroups: []string{"support"}}}, "from.example", &Identity{Email: "admin@admin-domain.com", ImpersonateGroups: []string{""}}, []string{"admin@admin-domain.com"}, "secret", false},
		// jwt validation
		{"bad jwt shared secret", []config.Policy{{From: "https://from.example", To: "https://to.example", AllowedDomains: []string{"example.com"}}}, "from.example", &Identity{Email: "user@example.com"}, nil, "bad-secret", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.policies {
				if err := (&tt.policies[i]).Validate(); err != nil {
					t.Fatal(err)
				}
			}
			key := []byte("secret")
			sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key},
				(&jose.SignerOptions{}).WithType("JWT"))
			if err != nil {
				t.Fatal(err)
			}

			cl := jwt.Claims{
				NotBefore: jwt.NewNumericDate(time.Now()),
				Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
				Audience:  jwt.Audience{tt.route},
			}
			rawJWT, err := jwt.Signed(sig).Claims(cl).Claims(tt.Identity).CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}

			data := map[string]interface{}{
				"route_policies": tt.policies,
				"admins":         tt.admins,
				"shared_key":     tt.secret,
			}
			pe, err := New(context.Background(), &Options{Data: data})
			if err != nil {
				t.Fatal(err)
			}
			req := &evaluator.Request{
				Host: tt.route,
				URL:  "https://" + tt.route,
				User: rawJWT,
			}
			got, err := pe.IsAuthorized(context.TODO(), req)
			if err != nil {
				t.Fatal(err)
			}
			if got.GetAllow() != tt.want {
				t.Errorf("pe.Eval() = %v, want %v", got.GetAllow(), tt.want)
			}
		})
	}
}

func Test_anyToInt(t *testing.T) {
	assert.Equal(t, 5, anyToInt("5"))
	assert.Equal(t, 7, anyToInt(7))
	assert.Equal(t, 9, anyToInt(int8(9)))
	assert.Equal(t, 9, anyToInt(int16(9)))
	assert.Equal(t, 9, anyToInt(int32(9)))
	assert.Equal(t, 9, anyToInt(int64(9)))
	assert.Equal(t, 11, anyToInt(uint8(11)))
	assert.Equal(t, 11, anyToInt(uint16(11)))
	assert.Equal(t, 11, anyToInt(uint32(11)))
	assert.Equal(t, 11, anyToInt(uint64(11)))
	assert.Equal(t, 13, anyToInt(13.0))
}
