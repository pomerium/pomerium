package log

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type connectInterceptor struct {
	logger *zerolog.Logger
}

// ConnectInterceptor logs connect calls.
func ConnectInterceptor(logger *zerolog.Logger) connect.Interceptor {
	return &connectInterceptor{
		logger: logger,
	}
}

func (i *connectInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx = i.logger.WithContext(ctx)
		start := time.Now()
		res, err := next(ctx, req)
		elapsed := time.Since(start)

		serviceName, methodName := splitFullMethodName(req.Spec().Procedure)

		evt := log.Ctx(ctx).Debug().
			Str("connect.service", serviceName).
			Str("connect.method", methodName).
			Dur("connect.duration", elapsed)

		if err != nil {
			evt = evt.Err(err).Str("connect.code", connect.CodeOf(err).String())
		}

		evt.Msg("finished call")

		return res, err
	}
}

func (i *connectInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		ctx = i.logger.WithContext(ctx)
		return next(ctx, spec)
	}
}

func (i *connectInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx = i.logger.WithContext(ctx)
		return next(ctx, conn)
	}
}
