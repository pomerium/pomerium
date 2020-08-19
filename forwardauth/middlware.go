package forwardauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/golang/protobuf/ptypes"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/rs/zerolog"
)

type authorizeResponse struct {
	authorized bool
	statusCode int32
}

func (fa *ForwardAuth) isAuthorized(w http.ResponseWriter, r *http.Request) (*authorizeResponse, error) {
	state := fa.state.Load()

	tm, err := ptypes.TimestampProto(time.Now())
	if err != nil {
		return nil, httputil.NewError(http.StatusInternalServerError, fmt.Errorf("error creating protobuf timestamp from current time: %w", err))
	}

	httpAttrs := &envoy_service_auth_v2.AttributeContext_HttpRequest{
		Method:   "GET",
		Headers:  map[string]string{},
		Path:     r.URL.Path,
		Host:     r.Host,
		Scheme:   r.URL.Scheme,
		Fragment: r.URL.Fragment,
	}
	for k := range r.Header {
		httpAttrs.Headers[k] = r.Header.Get(k)
	}
	if r.URL.RawQuery != "" {
		// envoy expects the query string in the path
		httpAttrs.Path += "?" + r.URL.RawQuery
	}

	res, err := state.authzClient.Check(r.Context(), &envoy_service_auth_v2.CheckRequest{
		Attributes: &envoy_service_auth_v2.AttributeContext{
			Request: &envoy_service_auth_v2.AttributeContext_Request{
				Time: tm,
				Http: httpAttrs,
			},
		},
	})
	if err != nil {
		return nil, httputil.NewError(http.StatusInternalServerError, err)
	}

	ar := &authorizeResponse{}
	switch res.HttpResponse.(type) {
	case *envoy_service_auth_v2.CheckResponse_OkResponse:
		for _, hdr := range res.GetOkResponse().GetHeaders() {
			w.Header().Set(hdr.GetHeader().GetKey(), hdr.GetHeader().GetValue())
		}
		ar.authorized = true
		ar.statusCode = res.GetStatus().Code
	case *envoy_service_auth_v2.CheckResponse_DeniedResponse:
		ar.statusCode = int32(res.GetDeniedResponse().GetStatus().Code)
	default:
		ar.statusCode = http.StatusInternalServerError
	}
	return ar, nil
}

// jwtClaimMiddleware logs and propagates JWT claim information via request headers.
func (fa *ForwardAuth) jwtClaimMiddleware(next http.Handler) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		defer next.ServeHTTP(w, r)

		state := fa.state.Load()
		jwt, err := sessions.FromContext(r.Context())
		if err != nil {
			log.Error().Err(err).Msg("proxy: could not locate session from context")
			return nil // best effort decoding
		}

		claims, err := jwtClaims(state.encoder, []byte(jwt))
		if err != nil {
			log.Error().Err(err).Msg("proxy: failed to format jwt claims")
			return nil // best effort formatting
		}

		// log group, email, user claims
		l := log.Ctx(r.Context())
		for _, claimName := range []string{"groups", "email", "user"} {
			l.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str(claimName, fmt.Sprintf("%v", claims[claimName]))
			})

		}

		// set headers for any claims specified by config
		for _, claimName := range state.jwtClaimHeaders {
			if _, ok := claims[claimName]; ok {
				headerName := fmt.Sprintf("x-pomerium-claim-%s", claimName)
				r.Header.Set(headerName, claims[claimName])
				w.Header().Add(headerName, claims[claimName])
			}
		}

		return nil
	})
}

// jwtClaims returns claims from given JWT value.
func jwtClaims(unmarshaler encoding.Unmarshaler, jwt []byte) (map[string]string, error) {
	claims := make(map[string]string)

	var jwtClaims map[string]interface{}
	if err := unmarshaler.Unmarshal(jwt, &jwtClaims); err != nil {
		return claims, err
	}

	for claim, value := range jwtClaims {
		var claimValue string
		if cv, ok := value.([]interface{}); ok {
			elements := make([]string, len(cv))

			for i, v := range cv {
				elements[i] = fmt.Sprintf("%v", v)
			}
			claimValue = strings.Join(elements, ",")
		} else {
			claimValue = fmt.Sprintf("%v", value)
		}
		claims[claim] = claimValue
	}

	return claims, nil
}
