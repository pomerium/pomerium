package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
)

const (
	// HeaderJWT is the header key containing JWT signed user details.
	HeaderJWT = "x-pomerium-jwt-assertion"
	// HeaderUserID is the header key containing the user's id.
	HeaderUserID = "x-pomerium-authenticated-user-id"
	// HeaderEmail is the header key containing the user's email.
	HeaderEmail = "x-pomerium-authenticated-user-email"
	// HeaderGroups is the header key containing the user's groups.
	HeaderGroups = "x-pomerium-authenticated-user-groups"

	disableCallback = "pomerium-auth-callback"
)

// AuthenticateSession is middleware to enforce a valid authentication
// session state is retrieved from the users's request context.
func (p *Proxy) AuthenticateSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := trace.StartSpan(r.Context(), "middleware.AuthenticateSession")
		defer span.End()
		s, err := sessions.FromContext(r.Context())
		if err != nil {
			log.Debug().Str("cause", err.Error()).Msg("proxy: re-authenticating due to session state error")
			p.reqNeedsAuthentication(w, r)
			return
		}
		if err := s.Valid(); err != nil {
			log.Debug().Str("cause", err.Error()).Msg("proxy: re-authenticating due to invalid session")
			p.reqNeedsAuthentication(w, r)
			return
		}
		// add pomerium's headers to the downstream request
		r.Header.Set(HeaderUserID, s.User)
		r.Header.Set(HeaderEmail, s.RequestEmail())
		r.Header.Set(HeaderGroups, s.RequestGroups())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthorizeSession is middleware to enforce a user is authorized for a request
// session state is retrieved from the users's request context.
func (p *Proxy) AuthorizeSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := trace.StartSpan(r.Context(), "middleware.AuthorizeSession")
		defer span.End()
		s, err := sessions.FromContext(r.Context())
		if err != nil {
			httputil.ErrorResponse(w, r.WithContext(ctx), httputil.Error("", http.StatusForbidden, err))
			return
		}
		authorized, err := p.AuthorizeClient.Authorize(r.Context(), r.Host, s)
		if err != nil {
			httputil.ErrorResponse(w, r.WithContext(ctx), err)
			return
		} else if !authorized {
			errMsg := fmt.Sprintf("%s is not authorized for this route", s.RequestEmail())
			httputil.ErrorResponse(w, r.WithContext(ctx), httputil.Error(errMsg, http.StatusForbidden, nil))
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SignRequest is middleware that signs a JWT that contains a user's id,
// email, and group. Session state is retrieved from the users's request context
func (p *Proxy) SignRequest(signer cryptutil.JWTSigner) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.SignRequest")
			defer span.End()
			s, err := sessions.FromContext(r.Context())
			if err != nil {
				httputil.ErrorResponse(w, r.WithContext(ctx), httputil.Error("", http.StatusForbidden, err))
				return
			}
			jwt, err := signer.SignJWT(s.User, s.Email, strings.Join(s.Groups, ","))
			if err != nil {
				log.Warn().Err(err).Msg("proxy: failed signing jwt")
			} else {
				r.Header.Set(HeaderJWT, jwt)
				w.Header().Set(HeaderJWT, jwt)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// reqNeedsAuthentication begins the authenticate flow, encrypting the
// redirect url in a request to the provider's sign in endpoint.
func (p *Proxy) reqNeedsAuthentication(w http.ResponseWriter, r *http.Request) {
	// some proxies like nginx won't follow redirects, and treat any
	// non 2xx or 4xx status as an internal service error.
	// https://nginx.org/en/docs/http/ngx_http_auth_request_module.html
	if _, ok := r.URL.Query()[disableCallback]; ok {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}
	uri := urlutil.SignedRedirectURL(p.SharedKey, p.authenticateSigninURL, urlutil.GetAbsoluteURL(r))
	http.Redirect(w, r, uri.String(), http.StatusFound)
}

// SetResponseHeaders sets a map of response headers.
func SetResponseHeaders(headers map[string]string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.SetResponseHeaders")
			defer span.End()
			for key, val := range headers {
				r.Header.Set(key, val)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
