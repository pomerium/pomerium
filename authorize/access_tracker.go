package authorize

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sets"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const (
	accessTrackerMaxSize        = 1_000
	accessTrackerDebouncePeriod = 10 * time.Second
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

	sessionAccesses := sets.NewSizeLimitedStringSet(tracker.maxSize)
	serviceAccountAccesses := sets.NewSizeLimitedStringSet(tracker.maxSize)
	runTrackSessionAccess := func(sessionID string) {
		sessionAccesses.Add(sessionID)
	}
	runTrackServiceAccountAccess := func(serviceAccountID string) {
		serviceAccountAccesses.Add(serviceAccountID)
	}
	runSubmit := func() {
		client := tracker.provider.GetDataBrokerServiceClient()
		now := timestamppb.Now()

		var err error

		sessionAccesses.ForEach(func(sessionID string) bool {
			err = tracker.put(ctx, client, &session.Session{
				Id:         sessionID,
				AccessedAt: now,
			})
			return err == nil
		})
		if err != nil {
			log.Error(ctx).Err(err).Msg("authorize: error updating session last access timestamp")
			return
		}

		serviceAccountAccesses.ForEach(func(serviceAccountID string) bool {
			err = tracker.put(ctx, client, &user.ServiceAccount{
				Id:         serviceAccountID,
				AccessedAt: now,
			})
			return err == nil
		})
		if err != nil {
			log.Error(ctx).Err(err).Msg("authorize: error updating service account last access timestamp")
			return
		}

		sessionAccesses = sets.NewSizeLimitedStringSet(tracker.maxSize)
		serviceAccountAccesses = sets.NewSizeLimitedStringSet(tracker.maxSize)
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
		// drop
	}
}

// TrackSessionAccess tracks a session access.
func (tracker *AccessTracker) TrackSessionAccess(sessionID string) {
	select {
	case tracker.sessionAccesses <- sessionID:
	default:
		// drop
	}
}

func (tracker *AccessTracker) put(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	object interface {
		proto.Message
		GetAccessedAt() *timestamppb.Timestamp
		GetId() string
	},
) error {
	any := protoutil.NewAny(object)
	_, err := client.Put(ctx, &databroker.PutRequest{
		Record: &databroker.Record{
			Type: any.TypeUrl,
			Id:   object.GetId(),
			Data: any,
		},
		Mask: &fieldmaskpb.FieldMask{
			Paths: []string{"accessed_at"},
		},
	})
	return err
}
