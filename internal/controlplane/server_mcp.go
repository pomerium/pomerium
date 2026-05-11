package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/libp2p/go-reuseport"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/httputil"
	"github.com/pomerium/pomerium/pkg/mcp/configapi"
)

// runMCPSupervisor owns the MCP ConfigService listener lifecycle. It
// reconciles the active listener against cfg.Options.MCPAddress on every
// signal from update(): binds/rebinds/unbinds transparently. The goroutine
// terminates when ctx is canceled.
func (srv *Server) runMCPSupervisor(ctx context.Context) error {
	var (
		cancel context.CancelFunc
		done   chan struct{}
		addr   string
	)
	stopCurrent := func() {
		if cancel != nil {
			cancel()
			<-done
			cancel = nil
			done = nil
			addr = ""
		}
	}
	defer stopCurrent()

	reconcile := func() {
		target := ""
		if cfg := srv.currentConfig.Load(); cfg != nil && cfg.Options != nil {
			target = cfg.Options.MCPAddress
		}
		if addr == target {
			return
		}
		if target == "" {
			stopCurrent()
			return
		}

		stopCurrent()

		l, err := reuseport.Listen("tcp4", target)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("addr", target).
				Msg("mcp: listener bind failed")
			return
		}
		h := configapi.NewHandler(srv.ConnectMux, configapi.WithRequestStamp(srv.newSharedKeyStamp()))

		addr = target
		listenCtx, c := context.WithCancel(ctx)
		cancel = c
		done = make(chan struct{})
		log.Ctx(ctx).Info().Str("addr", target).Msg("mcp: starting listener")
		go func() {
			defer close(done)
			if err := httputil.ServeWithGracefulStop(listenCtx, h, l, time.Second*5); err != nil {
				log.Ctx(listenCtx).Error().Err(err).Str("addr", target).Msg("mcp: listener exited with error")
			}
		}()
	}

	reconcile()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-srv.mcpReconcileCh:
			reconcile()
		}
	}
}

// newSharedKeyStamp returns a request-stamping function that signs a
// short-lived HS256 JWT with the current shared key and attaches it to the
// in-memory ConfigService request as a Pomerium-prefixed bearer token. This
// lets the downstream securedServer.authorize pass without bypassing auth.
//
// Any failure to obtain or sign the shared key is a gross misconfiguration
// (no shared key configured, signing primitive broken). The stamp returns
// a non-nil error in that case; the caller refuses the tool dispatch and
// surfaces a structured error to the MCP client, instead of silently
// sending an unauthenticated request that the downstream rejects with a
// generic auth failure the operator cannot diagnose.
func (srv *Server) newSharedKeyStamp() configapi.RequestStamp {
	return func(req *http.Request) error {
		cfg := srv.currentConfig.Load()
		if cfg == nil || cfg.Options == nil {
			return errors.New("mcp: no controlplane config loaded; cannot sign in-process Connect request")
		}
		key, err := cfg.Options.GetSharedKey()
		if err != nil {
			log.Ctx(req.Context()).Error().Err(err).
				Msg("mcp: resolve shared key for in-process Connect call")
			return fmt.Errorf("mcp: resolve shared key: %w", err)
		}
		if len(key) == 0 {
			log.Ctx(req.Context()).Error().
				Msg("mcp: shared key is empty; refusing to sign in-process Connect request")
			return errors.New("mcp: shared key is empty; configure shared_secret to use the MCP ConfigService listener")
		}
		rawjwt, err := signSharedKeyJWT(key)
		if err != nil {
			log.Ctx(req.Context()).Error().Err(err).
				Msg("mcp: sign shared-key JWT for in-process Connect call")
			return fmt.Errorf("mcp: sign shared-key JWT: %w", err)
		}
		req.Header.Set("Authorization", "Bearer Pomerium-"+rawjwt)
		return nil
	}
}

// signSharedKeyJWT produces a short-lived JWT signed with the shared key,
// acceptable to grpcutil.RequireSignedJWT on the receiving side. Mirrors the
// claims used by grpcutil.WithSignedJWT.
func signSharedKeyJWT(key []byte) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	return jwt.Signed(sig).Claims(jwt.Claims{
		Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).CompactSerialize()
}
