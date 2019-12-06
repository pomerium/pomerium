package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"fmt"
	"net/http"

	"github.com/pomerium/pomerium/internal/encoding"
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
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := trace.StartSpan(r.Context(), "proxy.AuthenticateSession")
		defer span.End()

		if s, err := sessions.FromContext(ctx); err != nil {
			log.FromRequest(r).Debug().Err(err).Msg("proxy: authenticate session")
			p.sessionStore.ClearSession(w, r)
			if s != nil && s.Programmatic {
				return httputil.NewError(http.StatusUnauthorized, err)
			}
			signinURL := *p.authenticateSigninURL
			q := signinURL.Query()
			q.Set(urlutil.QueryRedirectURI, urlutil.GetAbsoluteURL(r).String())
			signinURL.RawQuery = q.Encode()
			httputil.Redirect(w, r, urlutil.NewSignedURL(p.SharedKey, &signinURL).String(), http.StatusFound)
		}
		p.addPomeriumHeaders(w, r)
		next.ServeHTTP(w, r.WithContext(ctx))
		return nil
	})

}

func (p *Proxy) addPomeriumHeaders(w http.ResponseWriter, r *http.Request) {
	s, err := sessions.FromContext(r.Context())
	if err == nil && s != nil {
		r.Header.Set(HeaderUserID, s.Subject)
		r.Header.Set(HeaderEmail, s.RequestEmail())
		r.Header.Set(HeaderGroups, s.RequestGroups())
		w.Header().Set(HeaderUserID, s.Subject)
		w.Header().Set(HeaderEmail, s.RequestEmail())
		w.Header().Set(HeaderGroups, s.RequestGroups())
	}
}

// AuthorizeSession is middleware to enforce a user is authorized for a request
// session state is retrieved from the users's request context.
func (p *Proxy) AuthorizeSession(next http.Handler) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := trace.StartSpan(r.Context(), "proxy.AuthorizeSession")
		defer span.End()
		if err := p.authorize(r.Host, r.WithContext(ctx)); err != nil {
			log.FromRequest(r).Debug().Err(err).Msg("proxy: AuthorizeSession")
			return err
		}
		next.ServeHTTP(w, r.WithContext(ctx))
		return nil
	})
}

func (p *Proxy) authorize(host string, r *http.Request) error {
	s, err := sessions.FromContext(r.Context())
	if err != nil {
		return httputil.NewError(http.StatusUnauthorized, err)
	}
	authorized, err := p.AuthorizeClient.Authorize(r.Context(), host, s)
	if err != nil {
		return err
	} else if !authorized {
		return httputil.NewError(http.StatusUnauthorized, fmt.Errorf("%s is not authorized for %s", s.RequestEmail(), host))
	}
	return nil
}

// SignRequest is middleware that signs a JWT that contains a user's id,
// email, and group. Session state is retrieved from the users's request context
func (p *Proxy) SignRequest(signer encoding.Marshaler) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			ctx, span := trace.StartSpan(r.Context(), "proxy.SignRequest")
			defer span.End()
			s, err := sessions.FromContext(r.Context())
			if err != nil {
				return httputil.NewError(http.StatusForbidden, err)
			}
			newSession := s.NewSession(r.Host, []string{r.Host})
			jwt, err := signer.Marshal(newSession.RouteSession())
			if err != nil {
				log.FromRequest(r).Error().Err(err).Msg("proxy: failed signing jwt")
			} else {
				r.Header.Set(HeaderJWT, string(jwt))
				w.Header().Set(HeaderJWT, string(jwt))
			}
			next.ServeHTTP(w, r.WithContext(ctx))
			return nil
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
