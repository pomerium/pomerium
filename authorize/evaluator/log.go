package evaluator

import (
	"github.com/open-policy-agent/opa/v1/topdown/print"
	"github.com/rs/zerolog"
)

type regoPrintHook struct {
	logger zerolog.Logger
}

var _ print.Hook = (*regoPrintHook)(nil)

func (h regoPrintHook) Print(ctx print.Context, msg string) error {
	h.logger.Debug().
		Any("location", ctx.Location).
		Msg("rego: " + msg)
	return nil
}
