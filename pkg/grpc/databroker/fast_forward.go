package databroker

import (
	"context"
	"sync"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/slices"
)

// fastForwardHandler will skip
type fastForwardHandler struct {
	handler SyncerHandler
	pending chan ffCmd

	mu sync.Mutex
}

type ffCmd struct {
	clearRecords  bool
	serverVersion uint64
	records       []*Record
}

func newFastForwardHandler(ctx context.Context, handler SyncerHandler) SyncerHandler {
	ff := &fastForwardHandler{
		handler: handler,
		pending: make(chan ffCmd, 1),
	}
	go ff.run(ctx)
	return ff
}

func (ff *fastForwardHandler) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-ff.pending:
			if cmd.clearRecords {
				ff.handler.ClearRecords(ctx)
			} else {
				ff.handler.UpdateRecords(ctx, cmd.serverVersion, cmd.records)
			}
		}
	}
}

func (ff *fastForwardHandler) GetDataBrokerServiceClient() DataBrokerServiceClient {
	return ff.handler.GetDataBrokerServiceClient()
}

func (ff *fastForwardHandler) ClearRecords(ctx context.Context) {
	ff.mu.Lock()
	defer ff.mu.Unlock()

	var cmd ffCmd
	select {
	case <-ctx.Done():
		return
	case cmd = <-ff.pending:
	default:
	}
	cmd.clearRecords = true
	cmd.records = nil

	select {
	case <-ctx.Done():
	case ff.pending <- cmd:
	}
}

func (ff *fastForwardHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*Record) {
	ff.mu.Lock()
	defer ff.mu.Unlock()

	var cmd ffCmd
	select {
	case <-ctx.Done():
		return
	case cmd = <-ff.pending:
	default:
	}

	records = append(cmd.records, records...)
	// reverse, so that when we get the unique records, the newest take precedence
	slices.Reverse(records)
	cnt := len(records)
	records = slices.UniqueBy(records, func(record *Record) [2]string {
		return [2]string{record.GetType(), record.GetId()}
	})
	dropped := cnt - len(records)
	if dropped > 0 {
		log.Ctx(ctx).Info().Msgf("databroker: fast-forwarded %d records", dropped)
	}
	// reverse back so they appear in the order they were delivered
	slices.Reverse(records)

	cmd.clearRecords = false
	cmd.serverVersion = serverVersion
	cmd.records = records

	select {
	case <-ctx.Done():
	case ff.pending <- cmd:
	}
}
