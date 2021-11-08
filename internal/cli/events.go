package cli

import (
	"context"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/internal/log"
	pb "github.com/pomerium/pomerium/pkg/grpc/cli"
)

const (
	updateDeadline = time.Second
)

// EventBroadcaster is used to record and broadcast tunnel and connection state changes
type EventBroadcaster interface {
	// Reset the history for the connection, called when listener starts accepting new connections
	Reset(ctx context.Context, id string) error
	// Update provides a peer connection state change updates
	Update(ctx context.Context, evt *pb.ConnectionStatusUpdate) error
	// Subscribe to updates for the tunnel; the channel will close when context provided is canceled
	Subscribe(ctx context.Context, id string) (chan *pb.ConnectionStatusUpdate, error)
}

type subscriber struct {
	uuid.UUID
	context.Context
	connID string
	ch     chan *pb.ConnectionStatusUpdate
}

func (s *subscriber) close() {
	if s.ch == nil {
		return
	}

	close(s.ch)
	s.ch = nil
}

type events struct {
	byID    map[string]map[uuid.UUID]*subscriber
	history map[string][]*pb.ConnectionStatusUpdate
	updates chan *pb.ConnectionStatusUpdate
	subs    chan *subscriber
	reset   chan string
}

// NewEventsBroadcaster creates a new broadcaster
func NewEventsBroadcaster(ctx context.Context) EventBroadcaster {
	e := &events{
		byID:    make(map[string]map[uuid.UUID]*subscriber),
		history: make(map[string][]*pb.ConnectionStatusUpdate),
		updates: make(chan *pb.ConnectionStatusUpdate),
		subs:    make(chan *subscriber),
		reset:   make(chan string),
	}

	go e.run(ctx)
	return e
}

func (e *events) Reset(ctx context.Context, id string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case e.reset <- id:
		delete(e.history, id)
		return nil
	}
}

func (e *events) Update(ctx context.Context, evt *pb.ConnectionStatusUpdate) error {
	e.history[evt.Id] = append(e.history[evt.Id], evt)

	data, _ := protojson.Marshal(evt)
	log.Info(ctx).RawJSON("event", data).Msg("event broadcast")

	select {
	case <-ctx.Done():
		return ctx.Err()
	case e.updates <- evt:
		return nil
	}
}

// Subscribe to receiving channel updates for records within the given selector
// the channel would be closed and subscription removed  context is closed
//
// TODO: provide historical data between listener connect/disconnect
//
func (e *events) Subscribe(ctx context.Context, id string) (chan *pb.ConnectionStatusUpdate, error) {
	sub := &subscriber{
		UUID:    uuid.New(),
		Context: ctx,
		connID:  id,
		ch:      make(chan *pb.ConnectionStatusUpdate),
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case e.subs <- sub:
		return sub.ch, nil
	}
}

func (e *events) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			e.shutdown()
			return
		case evt := <-e.updates:
			if err := e.update(ctx, evt); err != nil {
				log.Error(ctx).Err(err).Msg("event broadcast: update")
			}
		case sub := <-e.subs:
			e.subscribe(sub)
		send_history:
			for _, evt := range e.history[sub.connID] {
				select {
				case <-ctx.Done():
					e.shutdown()
					return
				case <-sub.Done():
					e.unsubscribe(sub)
					break send_history
				case sub.ch <- evt:
				}
			}
		}
	}
}

func (e *events) subscribe(sub *subscriber) {
	m := e.byID[sub.connID]
	if m == nil {
		m = make(map[uuid.UUID]*subscriber)
		e.byID[sub.connID] = m
	}
	m[sub.UUID] = sub
}

func (e *events) unsubscribe(sub *subscriber) {
	sub.close()
	delete(e.byID[sub.connID], sub.UUID)
}

func (e *events) shutdown() {
	for _, m := range e.byID {
		for _, s := range m {
			s.close()
		}
	}
	e.byID = nil
}

func (e *events) update(ctx context.Context, evt *pb.ConnectionStatusUpdate) error {
	subs, there := e.byID[evt.Id]
	if !there || len(subs) == 0 {
		return nil
	}

	var cleanup []*subscriber

	for _, sub := range subs {
		if sub.Context.Err() != nil {
			cleanup = append(cleanup, sub)
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sub.Context.Done():
			cleanup = append(cleanup, sub)
			continue
		case <-time.After(updateDeadline):
			log.Error(sub.Context).Msg("timeout updating subscriber")
			cleanup = append(cleanup, sub)
			continue
		case sub.ch <- evt:
		}
	}

	for _, sub := range cleanup {
		e.unsubscribe(sub)
	}

	return nil
}
