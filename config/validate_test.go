package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestValidateTailscaleListenerSettings(t *testing.T) {
	t.Parallel()

	assert.ErrorContains(t,
		(&config.Options{
			TailscaleListeners: nullable.From([]config.TailscaleListenerSettings{
				{},
			}),
		}).ValidateTailscaleListenerSettings(),
		"tailscale_listeners[0]: tailscale_listener: auth_key, oauth_client_id or id_token must be set")
	assert.ErrorContains(t,
		(&config.Options{
			TailscaleListeners: nullable.From([]config.TailscaleListenerSettings{
				{
					AuthKey:       nullable.From("AUTH_KEY"),
					OauthClientID: nullable.From("OAUTH_CLIENT_ID"),
				},
			}),
		}).ValidateTailscaleListenerSettings(),
		"tailscale_listeners[0]: tailscale_listener: if auth_key is set, oauth_client_id and id_token should not be set")
	assert.ErrorContains(t,
		(&config.Options{
			TailscaleListeners: nullable.From([]config.TailscaleListenerSettings{
				{
					AuthKey: nullable.From("AUTH_KEY"),
					IDToken: nullable.From("ID_TOKEN"),
				},
			}),
		}).ValidateTailscaleListenerSettings(),
		"tailscale_listeners[0]: tailscale_listener: if auth_key is set, oauth_client_id and id_token should not be set")
	assert.ErrorContains(t,
		(&config.Options{
			TailscaleListeners: nullable.From([]config.TailscaleListenerSettings{
				{
					OauthClientID: nullable.From("OAUTH_CLIENT_ID"),
					IDToken:       nullable.From("ID_TOKEN"),
				},
			}),
		}).ValidateTailscaleListenerSettings(),
		"tailscale_listeners[0]: tailscale_listener: if oauth_client_id is set, auth_key and id_token should not be set")
	assert.ErrorContains(t,
		(&config.Options{
			TailscaleListeners: nullable.From([]config.TailscaleListenerSettings{
				{
					OauthClientID: nullable.From("OAUTH_CLIENT_ID"),
				},
			}),
		}).ValidateTailscaleListenerSettings(),
		"tailscale_listeners[0]: tailscale_listener: if oauth_client_id is set, oauth_client_secret must also be set")
	assert.ErrorContains(t,
		(&config.Options{
			TailscaleListeners: nullable.From([]config.TailscaleListenerSettings{
				{
					AuthKey:           nullable.From("AUTH_KEY"),
					OauthClientSecret: nullable.From("OAUTH_CLIENT_SECRET"),
				},
			}),
		}).ValidateTailscaleListenerSettings(),
		"tailscale_listeners[0]: tailscale_listener: if oauth_client_secret is set, oauth_client_id must also be set")
	assert.ErrorContains(t,
		(&config.Options{
			TailscaleListeners: nullable.From([]config.TailscaleListenerSettings{
				{
					AuthKey: nullable.From("AUTH_KEY"),
				},
			}),
		}).ValidateTailscaleListenerSettings(),
		"tailscale_listeners[0]: tailscale_listener: hostname must be non-empty")
}
