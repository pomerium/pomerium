package controlplane

import (
	"context"
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
		stopCurrent()
		if target == "" {
			return
		}

		l, err := reuseport.Listen("tcp4", target)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("addr", target).Msg("mcp: listener bind failed")
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
func (srv *Server) newSharedKeyStamp() func(*http.Request) {
	return func(req *http.Request) {
		cfg := srv.currentConfig.Load()
		if cfg == nil || cfg.Options == nil {
			return
		}
		key, err := cfg.Options.GetSharedKey()
		if err != nil || len(key) == 0 {
			return
		}
		rawjwt, err := signSharedKeyJWT(key)
		if err != nil {
			log.Ctx(req.Context()).Debug().Err(err).Msg("mcp: sign shared-key JWT")
			return
		}
		req.Header.Set("Authorization", "Bearer Pomerium-"+rawjwt)
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
