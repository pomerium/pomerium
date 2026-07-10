package postgresproxy

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// relay forwards the authenticated PostgreSQL session without inspecting SQL
// or buffering extended-query batches. Each direction has its own protocol
// reader and writer because pgproto3's combined frontend/backend values are not
// documented as safe for concurrent use.
func (s *Server) relay(
	ctx context.Context,
	session *Session,
	clientReader *pgproto3.Backend,
	clientConn net.Conn,
	upstreamReader *pgproto3.Frontend,
	upstreamConn net.Conn,
) error {
	clientWriter := pgproto3.NewBackend(clientConn, clientConn)
	upstreamWriter := pgproto3.NewFrontend(upstreamConn, upstreamConn)

	results := make(chan error, 2)
	go func() {
		results <- s.relayFrontendMessages(ctx, session, clientReader, upstreamWriter)
	}()
	go func() {
		results <- relayBackendMessages(ctx, upstreamReader, clientWriter)
	}()

	first := <-results
	// A PostgreSQL connection is one client socket mapped to one upstream
	// socket. When either direction ends, close both to unblock and terminate
	// the peer direction as well.
	_ = clientConn.Close()
	_ = upstreamConn.Close()
	second := <-results

	if err := normalizeRelayError(first); err != nil {
		return err
	}
	return normalizeRelayError(second)
}

func (s *Server) relayFrontendMessages(
	ctx context.Context,
	session *Session,
	client *pgproto3.Backend,
	upstream *pgproto3.Frontend,
) error {
	var boundaries reauthorizationBoundaries
	for {
		// The client-wait deadline remains armed until a complete protocol frame
		// is decoded. Partial headers or bodies are not active upstream work and
		// must not provide an authenticated slowloris bypass.
		msg, err := client.Receive()
		if err != nil {
			return err
		}
		activity := connectionActivityFromContext(ctx)
		if activity != nil {
			activity.frontendReceived(msg)
		}
		if boundaries.before(msg) {
			if err := s.reauthorize(ctx, session); err != nil {
				return err
			}
		}
		upstream.Send(msg)
		if err := upstream.Flush(); err != nil {
			return err
		}
		if _, ok := msg.(*pgproto3.Terminate); ok {
			return nil
		}
		if activity != nil {
			activity.frontendForwarded()
		}
	}
}

func relayBackendMessages(ctx context.Context, upstream *pgproto3.Frontend, client *pgproto3.Backend) error {
	for {
		msg, err := upstream.Receive()
		if err != nil {
			return err
		}
		client.Send(msg)
		if err := client.Flush(); err != nil {
			return err
		}
		if activity := connectionActivityFromContext(ctx); activity != nil {
			activity.backendForwarded(msg)
		}
	}
}

// reauthorizationBoundaries preserves session revocation checks without
// treating SQL or PostgreSQL metadata as a policy input. A simple Query or
// FunctionCall is an operation boundary. Extended protocol is checked before
// its first message after Sync and again before every Execute.
type reauthorizationBoundaries struct {
	inExtendedCycle bool
}

func (b *reauthorizationBoundaries) before(msg pgproto3.FrontendMessage) bool {
	switch msg.(type) {
	case *pgproto3.Query, *pgproto3.FunctionCall:
		b.inExtendedCycle = false
		return true
	case *pgproto3.Execute:
		b.inExtendedCycle = true
		return true
	case *pgproto3.Parse, *pgproto3.Bind, *pgproto3.Describe, *pgproto3.Close, *pgproto3.Flush:
		if b.inExtendedCycle {
			return false
		}
		b.inExtendedCycle = true
		return true
	case *pgproto3.Sync:
		b.inExtendedCycle = false
	}
	return false
}

func normalizeRelayError(err error) error {
	if errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
