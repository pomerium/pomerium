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
)

// AuthenticateSession is middleware to enforce a valid authentication
// session state is retrieved from the users's request context.
func (p *Proxy) AuthenticateSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := trace.StartSpan(r.Context(), "proxy.AuthenticateSession")
		defer span.End()
		if err := p.authenticate(w, r); err != nil {
			log.FromRequest(r).Debug().Err(err).Msg("proxy: authenticate session")
			uri := urlutil.SignedRedirectURL(p.SharedKey, p.authenticateSigninURL, urlutil.GetAbsoluteURL(r))
			http.Redirect(w, r, uri.String(), http.StatusFound)
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (p *Proxy) authenticate(w http.ResponseWriter, r *http.Request) error {
	s, err := sessions.FromContext(r.Context())
	if err != nil {
		return err
	}
	if s == nil {
		return fmt.Errorf("empty session state")
	}
	if err := s.Valid(); err != nil {
		return err
	}
	// add pomerium's headers to the downstream request
	r.Header.Set(HeaderUserID, s.User)
	r.Header.Set(HeaderEmail, s.RequestEmail())
	r.Header.Set(HeaderGroups, s.RequestGroups())
	// and upstream
	w.Header().Set(HeaderUserID, s.User)
	w.Header().Set(HeaderEmail, s.RequestEmail())
	w.Header().Set(HeaderGroups, s.RequestGroups())
	return nil
}

// AuthorizeSession is middleware to enforce a user is authorized for a request
// session state is retrieved from the users's request context.
func (p *Proxy) AuthorizeSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := trace.StartSpan(r.Context(), "proxy.AuthorizeSession")
		defer span.End()
		s, err := sessions.FromContext(r.Context())
		if err != nil || s == nil {
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
			ctx, span := trace.StartSpan(r.Context(), "proxy.SignRequest")
			defer span.End()
			s, err := sessions.FromContext(r.Context())
			if err != nil {
				httputil.ErrorResponse(w, r.WithContext(ctx), httputil.Error("", http.StatusForbidden, err))
				return
			}
			jwt, err := signer.SignJWT(s.User, s.Email, strings.Join(s.Groups, ","))
			if err != nil {
				log.FromRequest(r).Warn().Err(err).Msg("proxy: failed signing jwt")
			} else {
				r.Header.Set(HeaderJWT, jwt)
				w.Header().Set(HeaderJWT, jwt)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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
