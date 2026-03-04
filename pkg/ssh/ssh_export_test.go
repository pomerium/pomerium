package ssh

import (
	"context"

	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/api"
)

func (a *Auth) UnexportedHandlePublicKeyMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	user api.UserRequest,
	req *extensions_ssh.PublicKeyMethodRequest,
) (PublicKeyAuthMethodResponse, error) {
	return a.handlePublicKeyMethodRequest(ctx, info, user, req)
}

func (a *Auth) UnexportedHandleKeyboardInteractiveMethodRequest(
	ctx context.Context,
	info StreamAuthInfo,
	user api.UserRequest,
	querier KeyboardInteractiveQuerier,
) (KeyboardInteractiveAuthMethodResponse, error) {
	return a.handleKeyboardInteractiveMethodRequest(ctx, info, user, querier)
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

func (i *StreamAuthInfo) UnexportedAllMethodsValid() bool {
	return i.allMethodsValid()
}
