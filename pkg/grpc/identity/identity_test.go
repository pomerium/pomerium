package identity_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

func TestHash(t *testing.T) {
	t.Parallel()

	t.Run("excludes Id", func(t *testing.T) {
		t.Parallel()
		p1 := &identity.Provider{Id: "id1"}
		p2 := &identity.Provider{Id: "id2"}
		assert.Equal(t, p1.Hash(), p2.Hash(), "should ignore ids for hash")
	})

	t.Run("excludes AccessTokenAllowedAudiences", func(t *testing.T) {
		t.Parallel()

		base := &identity.Provider{
			ClientId:               "client-id",
			ClientSecret:           "client-secret",
			Type:                   "oidc",
			Url:                    "https://idp.example.com",
			AuthenticateServiceUrl: "https://auth.example.com",
		}

		withAudiences := &identity.Provider{
			ClientId:               "client-id",
			ClientSecret:           "client-secret",
			Type:                   "oidc",
			Url:                    "https://idp.example.com",
			AuthenticateServiceUrl: "https://auth.example.com",
			AccessTokenAllowedAudiences: &identity.Provider_StringList{
				Values: []string{"aud1", "aud2"},
			},
		}

		withDifferentAudiences := &identity.Provider{
			ClientId:               "client-id",
			ClientSecret:           "client-secret",
			Type:                   "oidc",
			Url:                    "https://idp.example.com",
			AuthenticateServiceUrl: "https://auth.example.com",
			AccessTokenAllowedAudiences: &identity.Provider_StringList{
				Values: []string{"aud3"},
			},
		}

		assert.Equal(t, base.Hash(), withAudiences.Hash(),
			"providers differing only in audiences should have the same hash")
		assert.Equal(t, base.Hash(), withDifferentAudiences.Hash(),
			"providers with different audiences should have the same hash")
	})

	t.Run("excludes AccessTokenAllowedAudiences nil vs empty", func(t *testing.T) {
		t.Parallel()

		withNil := &identity.Provider{
			ClientId: "client-id",
		}

		withEmpty := &identity.Provider{
			ClientId: "client-id",
			AccessTokenAllowedAudiences: &identity.Provider_StringList{
				Values: []string{},
			},
		}

		assert.Equal(t, withNil.Hash(), withEmpty.Hash(),
			"nil and empty audiences should produce the same hash")
	})

	t.Run("different ClientId produces different hash", func(t *testing.T) {
		t.Parallel()

		p1 := &identity.Provider{ClientId: "client-a"}
		p2 := &identity.Provider{ClientId: "client-b"}

		assert.NotEqual(t, p1.Hash(), p2.Hash(),
			"providers with different client IDs should have different hashes")
	})
}
