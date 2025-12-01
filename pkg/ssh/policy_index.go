package ssh

import (
	"context"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

//go:generate go run go.uber.org/mock/mockgen -typed -destination ./mock/mock_policy_index.go . PolicyIndexSubscriber

type PolicyIndexSubscriber interface {
	UpdateEnabledStaticPorts(allowedStaticPorts []uint)
	UpdateAuthorizedRoutes(routes []portforward.RouteInfo)
}

type PolicyIndexer interface {
	// Called once when the policy indexer should start, and should block until
	// the context is canceled or an implementation-specific graceful shutdown is
	// done, if supported. If stopped due to context cancellation, should return a
	// non-nil error, otherwise, this can return nil from a graceful shutdown.
	Run(ctx context.Context) error

	// Called once on startup, then again whenever the top-level configuration
	// changes.
	// This can be called in any order w.r.t. Run, OnStreamAuthenticated,
	// OnSessionCreated, and AddStream.
	ProcessConfigUpdate(cfg *config.Config)

	// Called when a stream has been authenticated successfully with a session.
	// The provided auth request will contain a non-empty session ID as well as
	// some other stream metadata.
	// This can be called in any order w.r.t. OnSessionCreated, AddStream, and
	// ProcessConfigUpdate.
	OnStreamAuthenticated(streamID uint64, req AuthRequest)

	// Called when a new session record is created and synced from the databroker.
	// This can be called in any order w.r.t. OnStreamAuthenticated, AddStream,
	// and ProcessConfigUpdate.
	OnSessionCreated(session *session.Session)

	// Called when an existing session (passed to OnSessionCreated previously)
	// is marked for deletion (due to revocation or manual logout) and synced from
	// the databroker.
	OnSessionDeleted(sessionID string)

	// Called when a new stream is connected. It may or may not be authenticated
	// or associated with a session yet. This will never be called twice with
	// the same stream ID; each active stream is given a unique ID.
	// This can be called in any order w.r.t. OnStreamAuthenticated,
	// OnSessionCreated, and ProcessConfigUpdate.
	//
	// To handle the PolicyIndexSubscriber:
	// - UpdateEnabledStaticPorts should be called once when the stream is
	//   authenticated and has a valid session. It should only be called again
	//   if the list of enabled ports changes. The list of enabled ports is
	//   generally the same for all streams and is unaffected by route policy.
	// - UpdateAuthorizedRoutes should be called whenever the list of authorized
	//   routes changes.
	//   The list of authorized routes may be non-empty iff the stream has a valid
	//   session AND it has been authenticated (i.e. both OnSessionCreated and
	//   OnStreamAuthenticated have been called for this stream).
	//   If the stream is not authenticated yet, or the session record has not
	//   been received yet (or has been deleted), the list of authorized routes
	//   MUST be empty.
	// - When AddStream is first called, the lists of enabled ports and authorized
	//   routes are implicitly empty. UpdateAuthorizedRoutes should not be called
	//   until the list of authorized routes has at least one entry. Likewise,
	//   UpdateEnabledStaticPorts should not be called until the list of enabled
	//   ports has at least one entry.
	AddStream(streamID uint64, sub PolicyIndexSubscriber)

	// Called when an existing stream (passed to AddStream previously) is
	// disconnected. When RemoveStream is called for a given stream ID, that ID
	// will never be reused. However, multiple streams can be authenticated to
	// the same session, and the session will outlive any of the streams
	// authenticated to it if those streams are closed before the session expires
	// or is deleted.
	// Upon the stream being removed, its authorized routes and enabled static
	// ports lists should now be considered empty, if they were not already.
	//
	// To handle the PolicyIndexSubscriber:
	// - Iff the most recent call to UpdateEnabledStaticPorts had been given a
	//   non-empty list of ports, call UpdateEnabledStaticPorts with an empty list
	//   or nil.
	// - Iff the most recent call to UpdateAuthorizedRoutes had been called with a
	//   non-empty list of routes, call UpdateAuthorizedRoutes with an empty list
	//   or nil.
	RemoveStream(streamID uint64, sub PolicyIndexSubscriber)
}
