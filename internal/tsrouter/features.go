package tsrouter

import (
	// tsnet only exchanges an id_token (or fetches one for id_token_audience)
	// for an auth key when this feature is registered. It isn't linked by
	// default because it pulls in cloud-provider SDKs.
	_ "tailscale.com/feature/identityfederation"
)
