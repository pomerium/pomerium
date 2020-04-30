package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/grpc/authorize"
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

func (p *Proxy) refresh(ctx context.Context, oldSession string) (string, error) {
	ctx, span := trace.StartSpan(ctx, "proxy.AuthenticateSession/refresh")
	defer span.End()
	s := &sessions.State{}
	if err := p.encoder.Unmarshal([]byte(oldSession), s); err != nil {
		return "", httputil.NewError(http.StatusBadRequest, err)
	}

	// 1 - build a signed url to call refresh on authenticate service
	refreshURI := *p.authenticateRefreshURL
	q := refreshURI.Query()
	q.Set(urlutil.QueryAccessTokenID, s.AccessTokenID)          // hash value points to parent token
	q.Set(urlutil.QueryAudience, strings.Join(s.Audience, ",")) // request's audience, this route
	refreshURI.RawQuery = q.Encode()
	signedRefreshURL := urlutil.NewSignedURL(p.SharedKey, &refreshURI).String()

	// 2 -  http call to authenticate service
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signedRefreshURL, nil)
	if err != nil {
		return "", fmt.Errorf("proxy: refresh request: %v", err)
	}

	req.Header.Set("X-Requested-With", "XmlHttpRequest")
	req.Header.Set("Accept", "application/json")
	res, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("proxy: client err %s: %w", signedRefreshURL, err)
	}
	defer res.Body.Close()
	newJwt, err := ioutil.ReadAll(io.LimitReader(res.Body, 4<<10))
	if err != nil {
		return "", err
	}
	// auth couldn't refersh the session, delete the session and reload via 302
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxy: backend refresh failed: %s", newJwt)
	}

	return string(newJwt), nil
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

// AuthorizeSession is middleware to enforce a user is authorized for a request.
// Session state is retrieved from the users's request context.
func (p *Proxy) AuthorizeSession(next http.Handler) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := trace.StartSpan(r.Context(), "proxy.AuthorizeSession")
		defer span.End()
		authz, err := p.authorize(w, r)
		if err != nil {
			return err
		}

		r.Header.Set(httputil.HeaderPomeriumJWTAssertion, authz.GetSignedJwt())
		next.ServeHTTP(w, r.WithContext(ctx))
		return nil
	})
}

func (p *Proxy) authorize(w http.ResponseWriter, r *http.Request) (*authorize.IsAuthorizedReply, error) {
	ctx, span := trace.StartSpan(r.Context(), "proxy.authorize")
	defer span.End()

	jwt, _ := sessions.FromContext(ctx)

	authz, err := p.AuthorizeClient.Authorize(ctx, jwt, r)
	if err != nil {
		return nil, httputil.NewError(http.StatusInternalServerError, err)
	}

	if authz.GetSessionExpired() {
		newJwt, err := p.refresh(ctx, jwt)
		if err != nil {
			p.sessionStore.ClearSession(w, r)
			log.FromRequest(r).Warn().Err(err).Msg("proxy: refresh failed")
			return nil, p.redirectToSignin(w, r)
		}
		if err = p.sessionStore.SaveSession(w, r, newJwt); err != nil {
			return nil, httputil.NewError(http.StatusUnauthorized, err)
		}

		authz, err = p.AuthorizeClient.Authorize(ctx, newJwt, r)
		if err != nil {
			return nil, httputil.NewError(http.StatusUnauthorized, err)
		}
	}
	if !authz.GetAllow() {
		log.FromRequest(r).Warn().
			Strs("reason", authz.GetDenyReasons()).
			Bool("allow", authz.GetAllow()).
			Bool("expired", authz.GetSessionExpired()).
			Msg("proxy/authorize: deny")
		return nil, httputil.NewError(http.StatusForbidden, errors.New("request denied"))
	}

	return authz, nil

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
