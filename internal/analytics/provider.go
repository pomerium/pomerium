package analytics

import (
	"context"
	"maps"

	"github.com/posthog/posthog-go"

	"github.com/pomerium/pomerium/internal/log"
)

// A Provider is an analytics provider.
type Provider interface {
	Close() error
	SendEvent(ctx context.Context, eventName EventName, installationID string, properties map[string]any)
}

type noOpProvider struct{}

// NewNoOpProvider creates a new analytics provider that simply logs events.
func NewNoOpProvider() Provider {
	return noOpProvider{}
}

func (p noOpProvider) Close() error {
	return nil
}

func (p noOpProvider) SendEvent(
	ctx context.Context,
	eventName EventName,
	installationID string,
	properties map[string]any,
) {
	log.Ctx(ctx).Debug().
		Str("event", string(eventName)).
		Str("installation-id", installationID).
		Any("properties", properties).
		Msg("analytics/noop: event")
}

type posthogProvider struct {
	client posthog.Client
}

// NewPostHogProvider creates a new analytics provider that sends events to posthog.
func NewPostHogProvider(client posthog.Client) Provider {
	return &posthogProvider{client: client}
}

func (p *posthogProvider) Close() error {
	return p.client.Close()
}

func (p *posthogProvider) SendEvent(
	ctx context.Context,
	eventName EventName,
	installationID string,
	properties map[string]any,
) {
	capture := posthog.Capture{
		DistinctId: installationID,
		Event:      string(eventName),
	}

	properties = maps.Clone(properties)
	capture.Groups = posthog.Groups{"installation": installationID}
	capture.Properties = posthog.Properties(properties)

	err := posthog.EnqueueWithContext(ctx, p.client, capture)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("analytics/posthog: failed to enqueue event")
	}
}
