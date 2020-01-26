package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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

		_, err := sessions.FromContext(ctx)
		if errors.Is(err, sessions.ErrExpired) {
			ctx, err = p.refresh(ctx, w, r)
			if err != nil {
				log.FromRequest(r).Warn().Err(err).Msg("proxy: refresh failed")
				return p.redirectToSignin(w, r)
			}
			log.FromRequest(r).Info().Msg("proxy: refresh success")
		} else if err != nil {
			log.FromRequest(r).Debug().Err(err).Msg("proxy: session state")
			return p.redirectToSignin(w, r)
		}
		p.addPomeriumHeaders(w, r)
		span.End()
		next.ServeHTTP(w, r.WithContext(ctx))
		return nil
	})
}

func (p *Proxy) refresh(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx, span := trace.StartSpan(ctx, "proxy.AuthenticateSession/refresh")
	defer span.End()
	s, err := sessions.FromContext(ctx)
	if !errors.Is(err, sessions.ErrExpired) || s == nil {
		return nil, errors.New("proxy: unexpected session state for refresh")
	}
	// 1 - build a signed url to call refresh on authenticate service
	refreshURI := *p.authenticateRefreshURL
	q := refreshURI.Query()
	q.Set(urlutil.QueryAccessTokenID, s.AccessTokenID)      // hash value points to parent token
	q.Set(urlutil.QueryAudience, urlutil.StripPort(r.Host)) // request's audience, this route
	refreshURI.RawQuery = q.Encode()
	signedRefreshURL := urlutil.NewSignedURL(p.SharedKey, &refreshURI).String()

	// 2 -  http call to authenticate service
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signedRefreshURL, nil)
	if err != nil {
		return nil, fmt.Errorf("proxy: refresh request: %v", err)
	}

	req.Header.Set("X-Requested-With", "XmlHttpRequest")
	req.Header.Set("Accept", "application/json")
	res, err := httputil.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxy: client err %s: %w", signedRefreshURL, err)
	}
	defer res.Body.Close()
	jwtBytes, err := ioutil.ReadAll(io.LimitReader(res.Body, 4<<10))
	if err != nil {
		return nil, err
	}
	// auth couldn't refersh the session, delete the session and reload via 302
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy: backend refresh failed: %s", jwtBytes)
	}

	// 3 - save refreshed session to the client's session store
	if err = p.sessionStore.SaveSession(w, r, jwtBytes); err != nil {
		return nil, err
	}
	// 4 - add refreshed session to the current request context
	var state sessions.State
	if err := p.encoder.Unmarshal(jwtBytes, &state); err != nil {
		return nil, err
	}
	if err := state.Verify(urlutil.StripPort(r.Host)); err != nil {
		return nil, err
	}
	return sessions.NewContext(r.Context(), &state, err), nil
}

func (p *Proxy) redirectToSignin(w http.ResponseWriter, r *http.Request) error {
	s, err := sessions.FromContext(r.Context())
	p.sessionStore.ClearSession(w, r)
	if s != nil && err != nil && s.Programmatic {
		return httputil.NewError(http.StatusUnauthorized, err)
	}
	signinURL := *p.authenticateSigninURL
	q := signinURL.Query()
	q.Set(urlutil.QueryRedirectURI, urlutil.GetAbsoluteURL(r).String())
	signinURL.RawQuery = q.Encode()
	log.FromRequest(r).Debug().Str("url", signinURL.String()).Msg("proxy: redirectToSignin")
	httputil.Redirect(w, r, urlutil.NewSignedURL(p.SharedKey, &signinURL).String(), http.StatusFound)
	return nil
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

// AuthorizeSession is middleware to enforce a user is authorized for a request.
// Session state is retrieved from the users's request context.
func (p *Proxy) AuthorizeSession(next http.Handler) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := trace.StartSpan(r.Context(), "proxy.AuthorizeSession")
		if err := p.authorize(r.Host, r.WithContext(ctx)); err != nil {
			log.FromRequest(r).Debug().Err(err).Msg("proxy: AuthorizeSession")
			return err
		}
		span.End()
		next.ServeHTTP(w, r.WithContext(ctx))
		return nil
	})
}

func (p *Proxy) authorize(host string, r *http.Request) error {
	s, err := sessions.FromContext(r.Context())
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}
	authorized, err := p.AuthorizeClient.Authorize(r.Context(), host, s)
	if err != nil {
		return err
	} else if !authorized {
		return httputil.NewError(http.StatusForbidden, fmt.Errorf("%s is not authorized for %s", s.RequestEmail(), host))
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
			span.End()
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
			span.End()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
