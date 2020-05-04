package proxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// AuthenticateSession is middleware to enforce a valid authentication
// session state is retrieved from the users's request context.
func (p *Proxy) AuthenticateSession(next http.Handler) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := trace.StartSpan(r.Context(), "proxy.AuthenticateSession")
		defer span.End()

		if _, err := sessions.FromContext(ctx); err != nil {
			log.FromRequest(r).Debug().Err(err).Msg("proxy: session state")
			return p.redirectToSignin(w, r)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
		return nil
	})
}

func (p *Proxy) redirectToSignin(w http.ResponseWriter, r *http.Request) error {
	signinURL := *p.authenticateSigninURL
	q := signinURL.Query()
	q.Set(urlutil.QueryRedirectURI, urlutil.GetAbsoluteURL(r).String())
	signinURL.RawQuery = q.Encode()
	log.FromRequest(r).Debug().Str("url", signinURL.String()).Msg("proxy: redirectToSignin")
	httputil.Redirect(w, r, urlutil.NewSignedURL(p.SharedKey, &signinURL).String(), http.StatusFound)
	p.sessionStore.ClearSession(w, r)
	return nil
}

// SetResponseHeaders sets a map of response headers.
func SetResponseHeaders(headers map[string]string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "proxy.SetResponseHeaders")
			defer span.End()
			for key, val := range headers {
				r.Header.Set(key, val)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// jwtClaimMiddleware logs and propagates JWT claim information via request headers
//
// if returnJWTInfo is set to true, it will also return JWT claim information in the response
func (p *Proxy) jwtClaimMiddleware(returnJWTInfo bool) mux.MiddlewareFunc {

	return func(next http.Handler) http.Handler {

		return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			defer next.ServeHTTP(w, r)

			jwt, err := sessions.FromContext(r.Context())
			if err != nil {
				log.Error().Err(err).Msg("proxy: could not locate session from context")
				return nil // best effort decoding
			}

			formattedJWTClaims, err := p.getFormatedJWTClaims([]byte(jwt))
			if err != nil {
				log.Error().Err(err).Msg("proxy: failed to format jwt claims")
				return nil // best effort formatting
			}

			// log group, email, user claims
			l := log.Ctx(r.Context())
			for _, claimName := range []string{"groups", "email", "user"} {

				l.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(claimName, fmt.Sprintf("%v", formattedJWTClaims[claimName]))
				})

			}

			// set headers for any claims specified by config
			for _, claimName := range p.jwtClaimHeaders {
				if _, ok := formattedJWTClaims[claimName]; ok {

					headerName := fmt.Sprintf("x-pomerium-claim-%s", claimName)
					r.Header.Set(headerName, formattedJWTClaims[claimName])
					if returnJWTInfo {
						w.Header().Add(headerName, formattedJWTClaims[claimName])
					}
				}
			}

			return nil
		})
	}
}

// getFormatJWTClaims reformats jwtClaims into something resembling map[string]string
func (p *Proxy) getFormatedJWTClaims(jwt []byte) (map[string]string, error) {
	formattedJWTClaims := make(map[string]string)

	var jwtClaims map[string]interface{}
	if err := p.encoder.Unmarshal(jwt, &jwtClaims); err != nil {
		return formattedJWTClaims, err
	}

	for claim, value := range jwtClaims {
		var formattedClaim string
		if cv, ok := value.([]interface{}); ok {
			elements := make([]string, len(cv))

			for i, v := range cv {
				elements[i] = fmt.Sprintf("%v", v)
			}
			formattedClaim = strings.Join(elements, ",")
		} else {
			formattedClaim = fmt.Sprintf("%v", value)
		}
		formattedJWTClaims[claim] = formattedClaim
	}

	return formattedJWTClaims, nil
}
