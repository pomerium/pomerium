package databroker

import (
	"context"

	"github.com/pomerium/pomerium/internal/log"
)

// fastForwardHandler will skip
type fastForwardHandler struct {
	handler SyncerHandler
	in      chan *ffCmd
	exec    chan *ffCmd
}

type ffCmd struct {
	clearRecords  bool
	serverVersion uint64
	records       []*Record
}

func newFastForwardHandler(ctx context.Context, handler SyncerHandler) SyncerHandler {
	ff := &fastForwardHandler{
		handler: handler,
		in:      make(chan *ffCmd, 20),
		exec:    make(chan *ffCmd),
	}
	go ff.runSelect(ctx)
	go ff.runExec(ctx)

	return ff
}

func (ff *fastForwardHandler) update(ctx context.Context, c *ffCmd) {
	ff.handler.UpdateRecords(ctx, c.serverVersion, c.records)
}

func (ff *fastForwardHandler) runSelect(ctx context.Context) {
	var update *ffCmd

	for {
		if update == nil {
			select {
			case <-ctx.Done():
				return
			case update = <-ff.in:
			}
		} else {
			select {
			case <-ctx.Done():
				return
			case update = <-ff.in:
			case ff.exec <- update:
				update = nil
			}
		}
	}
}

func (ff *fastForwardHandler) runExec(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case update := <-ff.exec:
			if update.clearRecords {
				ff.handler.ClearRecords(ctx)
				continue
			}
			ff.update(ctx, update)
		}
	}
}

func (ff *fastForwardHandler) GetDataBrokerServiceClient() DataBrokerServiceClient {
	return ff.handler.GetDataBrokerServiceClient()
}

func (ff *fastForwardHandler) ClearRecords(ctx context.Context) {
	select {
	case <-ctx.Done():
		log.Error(ctx).
			Msg("ff_handler: ClearRecords: context canceled")
	case ff.exec <- &ffCmd{clearRecords: true}:
	}
}

func (ff *fastForwardHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*Record) {
	select {
	case <-ctx.Done():
		log.Error(ctx).
			Msg("ff_handler: UpdateRecords: context canceled")
	case ff.in <- &ffCmd{serverVersion: serverVersion, records: records}:
	}
}
