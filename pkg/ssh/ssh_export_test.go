package ssh

import (
	"context"

	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
)

func (a *Auth) UnexportedHandlePublicKeyMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	req *extensions_ssh.PublicKeyMethodRequest,
) (PublicKeyAuthMethodResponse, error) {
	return a.handlePublicKeyMethodRequest(ctx, info, req)
}

func (a *Auth) UnexportedHandleKeyboardInteractiveMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	querier KeyboardInteractiveQuerier,
) (KeyboardInteractiveAuthMethodResponse, error) {
	return a.handleKeyboardInteractiveMethodRequest(ctx, info, querier)
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
