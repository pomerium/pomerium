package ssh

import (
	"context"

	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/api"
)

func (a *Auth) UnexportedHandlePublicKeyMethodRequest(
	ctx context.Context,
	streamInfo StreamInfo,
	authInfo StreamAuthInfo,
	user api.UserRequest,
	req *extensions_ssh.PublicKeyMethodRequest,
) (AuthMethodResponse, error) {
	return a.handlePublicKeyMethodRequest(ctx, streamInfo, authInfo, user, req)
}

func (sm *StreamManager) UnexportedEdsCache() *cache.LinearCache {
	return sm.edsCache
}

func (sm *StreamManager) UnexportedWaitForInitialSync(ctx context.Context) error {
	return sm.waitForInitialSync(ctx)
}

func (i *InMemoryPolicyIndexer) UnexportedState() *inMemoryIndexerState { //revive:disable-line:unexported-return
	return &i.state
}

var UnexportedSessionIDFromFingerprint = sessionIDFromFingerprint
