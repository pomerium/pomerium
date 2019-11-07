package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"fmt"
	"net/http"
	"time"

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
		if err := p.authenticate(false, w, r.WithContext(ctx)); err != nil {
			p.sessionStore.ClearSession(w, r)
			log.FromRequest(r).Debug().Err(err).Msg("proxy: authenticate session")
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})

}

// authenticate authenticates a user and sets an appropriate response type,
// redirect to authenticate or error handler depending on if err on failure is set.
func (p *Proxy) authenticate(errOnFailure bool, w http.ResponseWriter, r *http.Request) error {
	s, err := sessions.FromContext(r.Context())
	if err != nil {
		if errOnFailure || (s != nil && s.Programmatic) {
			httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusUnauthorized, err))
			return err
		}
		uri := urlutil.SignedRedirectURL(p.SharedKey, p.authenticateSigninURL, urlutil.GetAbsoluteURL(r))
		http.Redirect(w, r, uri.String(), http.StatusFound)
		return err
	}
	// add pomerium's headers to the downstream request
	r.Header.Set(HeaderUserID, s.Subject)
	r.Header.Set(HeaderEmail, s.RequestEmail())
	r.Header.Set(HeaderGroups, s.RequestGroups())
	// and upstream
	w.Header().Set(HeaderUserID, s.Subject)
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
		if err := p.authorize(r.Host, w, r.WithContext(ctx)); err != nil {
			log.FromRequest(r).Debug().Err(err).Msg("proxy: AuthorizeSession")
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (p *Proxy) authorize(host string, w http.ResponseWriter, r *http.Request) error {
	s, err := sessions.FromContext(r.Context())
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusUnauthorized, err))
		return err
	}
	authorized, err := p.AuthorizeClient.Authorize(r.Context(), host, s)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return err
	} else if !authorized {
		err = fmt.Errorf("%s is not authorized for %s", s.RequestEmail(), host)
		httputil.ErrorResponse(w, r, httputil.Error(err.Error(), http.StatusUnauthorized, err))
		return err
	}
	return nil
}

// SignRequest is middleware that signs a JWT that contains a user's id,
// email, and group. Session state is retrieved from the users's request context
func (p *Proxy) SignRequest(signer sessions.Marshaler) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "proxy.SignRequest")
			defer span.End()
			s, err := sessions.FromContext(r.Context())
			if err != nil {
				httputil.ErrorResponse(w, r.WithContext(ctx), httputil.Error("", http.StatusForbidden, err))
				return
			}
			newSession := s.NewSession(r.Host, []string{r.Host})
			jwt, err := signer.Marshal(newSession.RouteSession(time.Minute))
			if err != nil {
				log.FromRequest(r).Error().Err(err).Msg("proxy: failed signing jwt")
			} else {
				r.Header.Set(HeaderJWT, string(jwt))
				w.Header().Set(HeaderJWT, string(jwt))
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
