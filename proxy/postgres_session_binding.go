package proxy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/postgresidentity"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/postgresapi"
)

const (
	postgresBindingHandleMaxAge     = 5 * time.Minute
	postgresBindingHandleFutureSkew = time.Minute
)

func (p *Proxy) createPostgresSessionBinding(w http.ResponseWriter, r *http.Request) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return httputil.NewError(http.StatusUnsupportedMediaType, errors.New("content type must be application/json"))
	}

	r.Body = http.MaxBytesReader(w, r.Body, postgresapi.MaxCreateSessionBindingRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request postgresapi.CreateSessionBindingRequest
	if err := decoder.Decode(&request); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return httputil.NewError(http.StatusRequestEntityTooLarge, errors.New("request body is too large"))
		}
		return httputil.NewError(http.StatusBadRequest, errors.New("invalid request body"))
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return httputil.NewError(http.StatusBadRequest, errors.New("invalid request body"))
	}

	// Route selection, session verification, and binding persistence must use
	// one atomically published configuration generation.
	state := p.state.Load()
	route, routeHostname := postgresRouteForHostname(state.options, request.RouteHost)
	if route == nil || !state.options.IsRuntimeFlagSet(config.RuntimeFlagPostgres) {
		return httputil.NewError(http.StatusNotFound, errors.New("postgres route not found"))
	}
	idp, err := state.options.GetIdentityProviderForPolicy(route)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, errors.New("could not resolve postgres route identity provider"))
	}

	h, rawSessionHandle, err := readFreshPostgresBindingHandle(r, state, state.authenticateURL.Host, idp.GetId())
	if err != nil {
		return httputil.NewError(http.StatusUnauthorized, errors.New("valid fresh bearer session is required"))
	}
	identity, err := postgresidentity.ParseAndValidateCertificatePEM(
		[]byte(request.CertificatePEM), routeHostname, time.Now())
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}
	if err := validatePostgresSessionBindingProof(
		request.ProofSignature, routeHostname, rawSessionHandle, identity); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	binding, err := state.authenticateFlow.CreatePostgresSessionBinding(
		r.Context(), h, idp.GetId(), identity.BindingID, routeHostname, identity.Certificate.NotAfter)
	if errors.Is(err, authenticateflow.ErrPostgresSessionBindingUnsupported) {
		return httputil.NewError(http.StatusPreconditionFailed, err)
	}
	if errors.Is(err, authenticateflow.ErrPostgresSessionBindingInvalidSession) {
		return httputil.NewError(http.StatusUnauthorized, errors.New("valid fresh bearer session is required"))
	}
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, errors.New("could not create postgres session binding"))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(postgresapi.CreateSessionBindingResponse{
		BindingID: identity.BindingID,
		ExpiresAt: binding.GetExpiresAt().AsTime(),
	})
}

func readFreshPostgresBindingHandle(
	r *http.Request,
	state *proxyState,
	expectedIssuer, expectedIDP string,
) (*session.Handle, string, error) {
	const prefix = "Bearer Pomerium-"
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, prefix) || len(authorization) == len(prefix) {
		return nil, "", errors.New("exact bearer session is required")
	}
	rawSessionHandle := authorization[len(prefix):]

	// SessionStore also accepts cookies and query parameters. Construct a
	// header-only request so those weaker transports cannot win precedence.
	authRequest := r.Clone(r.Context())
	authRequest.Header = make(http.Header)
	authRequest.Header.Set("Authorization", authorization)
	authRequest.URL.RawQuery = ""
	h, err := state.sessionStore.ReadSessionHandle(authRequest)
	if err != nil {
		return nil, "", err
	}

	if expectedIssuer == "" || !strings.EqualFold(h.GetIss(), expectedIssuer) {
		return nil, "", errors.New("unexpected session issuer")
	}
	requestHost := urlutil.GetAbsoluteURL(r).Host
	if !containsFold(h.GetAud(), requestHost) {
		return nil, "", errors.New("unexpected session audience")
	}
	if expectedIDP == "" || h.GetIdentityProviderId() != expectedIDP {
		return nil, "", errors.New("unexpected session identity provider")
	}
	issuedAt := h.GetIat()
	if issuedAt == nil || issuedAt.AsTime().IsZero() {
		return nil, "", errors.New("session issued-at time is required")
	}
	now := time.Now()
	if issuedAt.AsTime().Before(now.Add(-postgresBindingHandleMaxAge)) ||
		issuedAt.AsTime().After(now.Add(postgresBindingHandleFutureSkew)) {
		return nil, "", errors.New("session handle is not fresh")
	}
	return h, rawSessionHandle, nil
}

func validatePostgresSessionBindingProof(
	encodedSignature, routeHostname, rawSessionHandle string,
	identity *postgresidentity.CertificateIdentity,
) error {
	invalid := errors.New("postgres session binding proof is invalid")
	if identity == nil || identity.Certificate == nil {
		return invalid
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(encodedSignature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawStdEncoding.EncodeToString(signature) != encodedSignature {
		return invalid
	}
	publicKey, ok := identity.Certificate.PublicKey.(ed25519.PublicKey)
	if !ok {
		return invalid
	}
	message, err := postgresapi.SessionBindingProofMessage(
		routeHostname, rawSessionHandle, identity.Certificate.Raw)
	if err != nil || !ed25519.Verify(publicKey, message, signature) {
		return invalid
	}
	return nil
}

func postgresRouteForHostname(options *config.Options, hostname string) (*config.Policy, string) {
	if options == nil {
		return nil, ""
	}
	hostname, err := postgresidentity.ValidateRouteHostname(hostname)
	if err != nil {
		return nil, ""
	}
	route := options.GetRouteForPostgresHostname(hostname)
	if route == nil {
		return nil, ""
	}
	from, err := urlutil.ParseAndValidateURL(route.From)
	if err != nil || from.Hostname() == "" {
		return nil, ""
	}
	return route, postgresidentity.CanonicalHostname(from.Hostname())
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}
