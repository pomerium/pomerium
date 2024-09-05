package authorize

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sets"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

const (
	accessTrackerMaxSize        = 1_000
	accessTrackerDebouncePeriod = 10 * time.Second
	accessTrackerUpdateTimeout  = 3 * time.Second
)

// A AccessTrackerProvider provides the databroker service client for tracking session access.
type AccessTrackerProvider interface {
	GetDataBrokerServiceClient() databroker.DataBrokerServiceClient
}

// A AccessTracker tracks accesses to sessions
type AccessTracker struct {
	provider               AccessTrackerProvider
	sessionAccesses        chan string
	serviceAccountAccesses chan string
	maxSize                int
	debouncePeriod         time.Duration

	droppedAccesses int64
}

// NewAccessTracker creates a new SessionAccessTracker.
func NewAccessTracker(
	provider AccessTrackerProvider,
	maxSize int,
	debouncePeriod time.Duration,
) *AccessTracker {
	return &AccessTracker{
		provider:               provider,
		sessionAccesses:        make(chan string, maxSize),
		serviceAccountAccesses: make(chan string, maxSize),
		maxSize:                maxSize,
		debouncePeriod:         debouncePeriod,
	}
}

// Run runs the access tracker.
func (tracker *AccessTracker) Run(ctx context.Context) {
	ticker := time.NewTicker(tracker.debouncePeriod)
	defer ticker.Stop()

	sessionAccesses := sets.NewSizeLimited[string](tracker.maxSize)
	serviceAccountAccesses := sets.NewSizeLimited[string](tracker.maxSize)
	runTrackSessionAccess := func(sessionID string) {
		sessionAccesses.Add(sessionID)
	}
	runTrackServiceAccountAccess := func(serviceAccountID string) {
		serviceAccountAccesses.Add(serviceAccountID)
	}
	runSubmit := func() {
		if dropped := atomic.SwapInt64(&tracker.droppedAccesses, 0); dropped > 0 {
			log.Ctx(ctx).Error().
				Int64("dropped", dropped).
				Msg("authorize: failed to track all session accesses")
		}

		client := tracker.provider.GetDataBrokerServiceClient()

		var err error

		sessionAccesses.ForEach(func(sessionID string) bool {
			err = tracker.updateSession(ctx, client, sessionID)
			return err == nil
		})
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("authorize: error updating session last access timestamp")
			return
		}

		serviceAccountAccesses.ForEach(func(serviceAccountID string) bool {
			err = tracker.updateServiceAccount(ctx, client, serviceAccountID)
			return err == nil
		})
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("authorize: error updating service account last access timestamp")
			return
		}

		sessionAccesses = sets.NewSizeLimited[string](tracker.maxSize)
		serviceAccountAccesses = sets.NewSizeLimited[string](tracker.maxSize)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case id := <-tracker.sessionAccesses:
			runTrackSessionAccess(id)
		case id := <-tracker.serviceAccountAccesses:
			runTrackServiceAccountAccess(id)
		case <-ticker.C:
			runSubmit()
		}
	}
}

// TrackServiceAccountAccess tracks a service account access.
func (tracker *AccessTracker) TrackServiceAccountAccess(serviceAccountID string) {
	select {
	case tracker.serviceAccountAccesses <- serviceAccountID:
	default:
		atomic.AddInt64(&tracker.droppedAccesses, 1)
	}
}

// TrackSessionAccess tracks a session access.
func (tracker *AccessTracker) TrackSessionAccess(sessionID string) {
	select {
	case tracker.sessionAccesses <- sessionID:
	default:
		atomic.AddInt64(&tracker.droppedAccesses, 1)
	}
}

func (tracker *AccessTracker) updateServiceAccount(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	serviceAccountID string,
) error {
	ctx, clearTimeout := context.WithTimeout(ctx, accessTrackerUpdateTimeout)
	defer clearTimeout()

	sa, err := user.GetServiceAccount(ctx, client, serviceAccountID)
	if status.Code(err) == codes.NotFound {
		return nil
	} else if err != nil {
		return err
	}
	sa.AccessedAt = timestamppb.Now()
	_, err = user.PutServiceAccount(ctx, client, sa)
	return err
}

func (tracker *AccessTracker) updateSession(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	sessionID string,
) error {
	ctx, clearTimeout := context.WithTimeout(ctx, accessTrackerUpdateTimeout)
	defer clearTimeout()

	s := &session.Session{Id: sessionID, AccessedAt: timestamppb.Now()}
	m, err := fieldmaskpb.New(s, "accessed_at")
	if err != nil {
		return fmt.Errorf("internal error: %w", err)
	}

	_, err = session.Patch(ctx, client, s, m)
	return err
}
