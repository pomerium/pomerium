package authenticateflow

import (
	"context"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh/code"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// Stateful implements the stateful authentication flow. In this flow, the
// authenticate service has direct access to the databroker.
type Stateful struct {
	signatureVerifier

	// sharedEncoder is the encoder to use to serialize data to be consumed
	// by other services
	sharedEncoder encoding.MarshalUnmarshaler
	// sharedKey is the secret to encrypt and authenticate data shared between services
	sharedKey []byte
	// sharedCipher is the cipher to use to encrypt/decrypt data shared between services
	sharedCipher cipher.AEAD
	// sessionDuration is the maximum Pomerium session duration
	sessionDuration time.Duration
	// sessionStore is the session store used to persist a user's session
	sessionStore sessions.HandleWriter

	authenticateURL *url.URL

	dataBrokerClient databroker.DataBrokerServiceClient

	defaultIdentityProviderID string

	codeReader  code.Reader
	codeRevoker code.Revoker

	signInHandler     SSHSignInHandler
	dataBrokerQuerier func() storage.Querier
}

type StatefulFlowOptions struct {
	signInHandler     SSHSignInHandler
	dataBrokerQuerier func() storage.Querier
}

func (s *StatefulFlowOptions) Apply(opts ...StatefulFlowOption) {
	for _, opt := range opts {
		opt(s)
	}
}

type StatefulFlowOption func(*StatefulFlowOptions)

func WithSSHSignInHandler(handler SSHSignInHandler) StatefulFlowOption {
	return func(sfo *StatefulFlowOptions) {
		sfo.signInHandler = handler
	}
}

// WithDataBrokerQuerier supplies a same-process querier whose synchronized
// view should be invalidated by stateful flow writes.
func WithDataBrokerQuerier(get func() storage.Querier) StatefulFlowOption {
	return func(sfo *StatefulFlowOptions) {
		sfo.dataBrokerQuerier = get
	}
}

// NewStateful initializes the authentication flow for the given configuration
// and session store.
func NewStateful(
	ctx context.Context,
	tracerProvider oteltrace.TracerProvider,
	cfg *config.Config,
	sessionStore sessions.HandleWriter,
	outboundGrpcConn *grpc.CachedOutboundGRPClientConn,
	opts ...StatefulFlowOption,
) (*Stateful, error) {
	options := &StatefulFlowOptions{
		signInHandler: &defaultSignInHandler{},
	}

	options.Apply(opts...)

	s := &Stateful{
		sessionDuration:   cfg.Options.CookieExpire,
		sessionStore:      sessionStore,
		signInHandler:     options.signInHandler,
		dataBrokerQuerier: options.dataBrokerQuerier,
	}

	var err error
	s.authenticateURL, err = cfg.Options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}
	// shared cipher to encrypt data before passing data between services
	s.sharedKey, err = cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}
	s.sharedCipher, err = cryptutil.NewAEADCipher(s.sharedKey)
	if err != nil {
		return nil, err
	}
	// shared state encoder setup
	s.sharedEncoder, err = jws.NewHS256Signer(s.sharedKey)
	if err != nil {
		return nil, err
	}
	s.signatureVerifier = signatureVerifier{cfg.Options, s.sharedKey}

	idp, err := cfg.Options.GetIdentityProviderForPolicy(nil)
	if err == nil {
		s.defaultIdentityProviderID = idp.GetId()
	}

	dataBrokerConn, err := outboundGrpcConn.Get(ctx,
		&grpc.OutboundOptions{
			OutboundPort:   cfg.OutboundPort,
			InstallationID: cfg.Options.InstallationID,
			ServiceName:    cfg.Options.Services,
			SignedJWTKey:   s.sharedKey,
		}, googlegrpc.WithStatsHandler(trace.NewClientStatsHandler(
			otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(tracerProvider)),
			outboundDatabrokerTraceClientOpts...,
		)))
	if err != nil {
		return nil, err
	}

	s.dataBrokerClient = databroker.NewDataBrokerServiceClient(dataBrokerConn)
	s.codeReader = code.NewReader(databroker.NewStaticClientGetter(s.dataBrokerClient))
	s.codeRevoker = code.NewRevoker(databroker.NewStaticClientGetter(s.dataBrokerClient))
	return s, nil
}

// SignIn redirects to a route callback URL, if the provided request and
// session handle are valid.
func (s *Stateful) SignIn(
	w http.ResponseWriter,
	r *http.Request,
	h *session.Handle,
) error {
	if err := s.VerifyAuthenticateSignature(r); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	idpID := r.FormValue(urlutil.QueryIdentityProviderID)

	// start over if this is a different identity provider
	if h == nil || h.IdentityProviderId != idpID {
		h = session.NewHandle(idpID)
	}

	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue(urlutil.QueryRedirectURI))
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	jwtAudience := []string{s.authenticateURL.Host, redirectURL.Host}

	// if the callback is explicitly set, set it and add an additional audience
	if callbackStr := r.FormValue(urlutil.QueryCallbackURI); callbackStr != "" {
		callbackURL, err := urlutil.ParseAndValidateURL(callbackStr)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}
		jwtAudience = append(jwtAudience, callbackURL.Host)
	}

	newSession := h.WithNewIssuer(s.authenticateURL.Host, jwtAudience)

	// re-persist the session, useful when session was evicted from session store
	if err := s.sessionStore.WriteSessionHandle(w, h); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// sign the route session, as a JWT
	signedJWT, err := s.sharedEncoder.Marshal(newSession)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// encrypt our route-scoped JWT to avoid accidental logging of queryparams
	encryptedJWT := cryptutil.Encrypt(s.sharedCipher, signedJWT, nil)
	// base64 our encrypted payload for URL-friendlyness
	encodedJWT := base64.URLEncoding.EncodeToString(encryptedJWT)

	additionalHosts := strings.Split(r.FormValue(urlutil.QueryAdditionalHosts), ",")

	callbackURL, err := urlutil.GetCallbackURL(r, encodedJWT, additionalHosts)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	// build our hmac-d redirect URL with our session, pointing back to the
	// proxy's callback URL which is responsible for setting our new route-session
	uri := urlutil.NewSignedURL(s.sharedKey, callbackURL)
	httputil.Redirect(w, r, uri.String(), http.StatusFound)
	return nil
}

func getSessionBindingRequestID(r *http.Request) string {
	query := r.URL.Query()
	if query.Has(urlutil.QueryBindSession) {
		sbrID := query.Get(urlutil.QueryBindSession)
		return sbrID
	}
	return query.Get("user_code")
}

func (s *Stateful) AuthenticatePendingSession(
	w http.ResponseWriter,
	r *http.Request,
	h *session.Handle,
) error {
	sbrID := getSessionBindingRequestID(r)
	sbr, ok := s.codeReader.GetBindingRequest(r.Context(), code.CodeID(sbrID))
	if !ok {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("code invalid"))
	}
	if sbr.State != session.SessionBindingRequestState_InFlight {
		return httputil.NewError(http.StatusConflict, fmt.Errorf("code already processed"))
	}
	now := time.Now()
	if sbr.ExpiresAt.AsTime().Before(now) {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("expired"))
	}

	identityBinding, hasIdentity, err := s.hasIdentityBinding(r.Context(), sbr)
	if err != nil {
		return err
	}
	if hasIdentity {
		if !isValidIdentity(identityBinding, h, sbr) {
			identityBinding = nil
		}
	}
	confirmed := false
	createIdentityBinding := false
	switch r.Method {
	case http.MethodGet:
		if identityBinding == nil {
			s.handleSignIn(w, r, h, sbr)
			return nil
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return err
		}
		confirmed = r.Form.Get("confirm") == "true"
		createIdentityBinding = r.Form.Get("create_id_binding") == "true"
	default:
		return httputil.NewError(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}

	recordsToProcess := []*databroker.Record{}
	if createIdentityBinding {
		recordsToProcess = append(recordsToProcess, s.associateIdentity(sbr.Key, h))
	}
	// code confirmed or identity was already persisted.
	authenticated := confirmed || identityBinding != nil
	var expiresAt *time.Time
	if authenticated {
		sbr.State = session.SessionBindingRequestState_Accepted
		sessionBinding, expiryTime, err := s.associateSessionBinding(r.Context(), h, sbr)
		if err != nil {
			return httputil.NewError(http.StatusBadRequest, err)
		}
		expiresAt = &expiryTime
		recordsToProcess = append(recordsToProcess, sessionBinding)
	} else {
		sbr.State = session.SessionBindingRequestState_Revoked
	}

	// never expires when user sets "remember me"
	if identityBinding != nil || createIdentityBinding {
		expiresAt = nil
	}

	// sbr / code is always processed
	recordsToProcess = append(recordsToProcess, &databroker.Record{
		Id:   sbrID,
		Type: grpcutil.GetTypeURL(sbr),
		Data: protoutil.NewAny(sbr),
	})

	if _, err := s.dataBrokerClient.Put(r.Context(), &databroker.PutRequest{
		Records: recordsToProcess,
	}); err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	session, user, _ := s.GetSessionAndUser(r, h)

	if authenticated {
		s.signInHandler.SuccessRedirect(w, r, SignSuccessRawData{
			Session:   session,
			User:      user,
			Sbr:       sbr,
			ExpiresAt: expiresAt,
		})
	} else {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("revoked"))
	}
	return nil
}

func isValidIdentity(
	ib *session.IdentityBinding,
	h *session.Handle,
	sbr *session.SessionBindingRequest,
) bool {
	return ib.IdpId == h.IdentityProviderId &&
		ib.Protocol == sbr.Protocol &&
		ib.UserId == h.UserId
}

func (s *Stateful) hasIdentityBinding(
	ctx context.Context,
	sbr *session.SessionBindingRequest,
) (*session.IdentityBinding, bool, error) {
	var identityBinding session.IdentityBinding
	resp, err := s.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.IdentityBinding",
		Id:   sbr.Key,
	})
	if databroker.IsNotFound(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, httputil.NewError(http.StatusInternalServerError, err)
	}
	if err := resp.GetRecord().GetData().UnmarshalTo(&identityBinding); err != nil {
		return nil, false, err
	}
	return &identityBinding, true, nil
}

func (s *Stateful) associateIdentity(bindingID string, h *session.Handle) *databroker.Record {
	ib := session.IdentityBinding{
		Protocol: session.ProtocolSSH,
		UserId:   h.UserId,
		IdpId:    h.IdentityProviderId,
	}
	return &databroker.Record{
		Type: "type.googleapis.com/session.IdentityBinding",
		Id:   bindingID,
		Data: protoutil.NewAny(&ib),
	}
}

func (s *Stateful) handleSignIn(
	w http.ResponseWriter,
	r *http.Request,
	h *session.Handle,
	sbr *session.SessionBindingRequest,
) {
	redirect := r.URL
	handlers.SignInVerify(handlers.SignInVerifyData{
		UserInfoData: s.GetUserInfoData(r, h),
		RedirectURL:  redirect.String(),
		IssuedAt:     sbr.CreatedAt.AsTime(),
		ExpiresAt:    sbr.ExpiresAt.AsTime(),
		SourceAddr:   sbr.Details[session.DetailSourceAddr],
		Protocol:     sbr.Protocol,
	}).ServeHTTP(w, r)
}

func (s *Stateful) associateSessionBinding(
	ctx context.Context,
	h *session.Handle,
	sbr *session.SessionBindingRequest,
) (rec *databroker.Record, expiresAt time.Time, err error) {
	sessionID := sbr.Key

	expiry, err := s.sessionExpiresAt(ctx, h)
	if err != nil {
		return nil, time.Time{}, err
	}
	if expiry == nil {
		defaultT := time.Now().Add(time.Hour * 48)
		expiry = &defaultT
	}
	return &databroker.Record{
		Type: "type.googleapis.com/session.SessionBinding",
		Id:   sessionID,
		Data: protoutil.NewAny(&session.SessionBinding{
			Protocol:  session.ProtocolSSH,
			SessionId: h.Id,
			IssuedAt:  timestamppb.New(h.Iat.AsTime()),
			ExpiresAt: timestamppb.New(*expiry),
			UserId:    h.UserId,
			Details:   sbr.GetDetails(),
		}),
	}, *expiry, nil
}

func (s *Stateful) GetSessionBindingInfo(w http.ResponseWriter, r *http.Request, h *session.Handle) error {
	sshData, err := s.getLegacySSHSessionBindingInfo(r.Context(), h.UserId, *r.URL)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}
	otherBindings, err := s.getIDPSessionBindings(r.Context(), h.UserId, *r.URL)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	all := append(sshData, otherBindings...)
	handlers.ServeSessionBindingInfo(handlers.SessionInfoData{
		UserInfoData: s.GetUserInfoData(r, h),
		SessionData:  all,
	}).ServeHTTP(w, r)
	return nil
}

func (s *Stateful) getIDPSessionBindings(ctx context.Context, userID string, redirectBase url.URL) ([]handlers.SessionBindingData, error) {
	idpSession := &idpsession.IDPSession{Id: userID}
	if err := databroker.Get(ctx, s.dataBrokerClient, idpSession); err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("could not fetch IDP session: %w", err)
	}

	filter, err := structpb.NewStruct(map[string]any{
		"idp_session_id": idpSession.GetId(),
	})
	if err != nil {
		return nil, fmt.Errorf("could not build IDP session binding filter: %w", err)
	}
	response, err := s.dataBrokerClient.Query(ctx, &databroker.QueryRequest{
		Type:   protoutil.GetTypeURL(&idpsession.Binding{}),
		Filter: filter,
		Limit:  100,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("could not fetch IDP session bindings: %w", err)
	}

	renderData := make([]handlers.SessionBindingData, 0, len(response.GetRecords()))
	for _, record := range response.GetRecords() {
		if record.GetDeletedAt() != nil {
			continue
		}

		binding := new(idpsession.Binding)
		if err := record.GetData().UnmarshalTo(binding); err != nil {
			return nil, fmt.Errorf("could not decode IDP session binding %q: %w", record.GetId(), err)
		}
		bindingType := binding.GetTypeUrl()
		if binding.GetState() == idpsession.BindingState_BindingState_REVOKED {
			continue
		}
		// not user visible session
		if bindingType != "type.googleapis.com/session.Session" {
			continue
		}

		datum, err := s.sessionToBindingData(ctx, binding, redirectBase)
		if err != nil {
			log.Ctx(ctx).Err(err).Msg("failed to fetch session binding information")
			continue
		}
		renderData = append(renderData, datum)
	}

	sort.Slice(renderData, func(i, j int) bool {
		if renderData[i].Protocol != renderData[j].Protocol {
			return renderData[i].Protocol < renderData[j].Protocol
		}
		return renderData[i].SessionBindingID < renderData[j].SessionBindingID
	})
	return renderData, nil
}

func (s *Stateful) sessionToBindingData(
	ctx context.Context,
	binding *idpsession.Binding,
	redirectBase url.URL,
) (handlers.SessionBindingData, error) {
	var expiresAt string
	var clientAddr string
	var resource string

	switch binding.GetTypeUrl() {
	case protoutil.GetTypeURL(&session.Session{}):
		rec, err := s.dataBrokerClient.Get(ctx, &databroker.GetRequest{
			Type: protoutil.GetTypeURL(&session.Session{}),
			Id:   binding.GetId(),
		})
		if err != nil {
			return handlers.SessionBindingData{}, nil
		}
		switch binding.GetProtocol() {
		case idpsession.BindingProtocol_BINDING_PROTOCOL_MCP:
			// TODO : we can look up the idpsession here and get the access_token expiry which becomes
			// the real expire here
			expiresAt = "Until revoked or IDP expires"
			resource = binding.GetDetails()["mcp_client_id"]
		case idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER:
			sess := &session.Session{}
			if err := rec.GetRecord().GetData().UnmarshalTo(sess); err != nil {
				return handlers.SessionBindingData{}, nil
			}
			expiresAt = sess.GetExpiresAt().AsTime().Format(time.RFC1123)
			resource = formatBrowserUserAgent(binding.GetDetails()["user-agent"])
		}
		clientAddr = binding.GetDetails()["client-ip"]
	}
	redirectRevoke := redirectBase
	redirectRevoke.Path = "/.pomerium/session_binding/revoke"
	datum := handlers.SessionBindingData{
		SessionBindingID:        binding.GetId(),
		Protocol:                formatProtocol(binding.GetProtocol()),
		ClientAddress:           clientAddr,
		ExpiresAt:               expiresAt,
		RevokeSessionBindingURL: redirectRevoke.String(),
		Resource:                resource,
	}

	if binding.GetInitiatedAt() != nil {
		datum.InitiatedAt = binding.GetInitiatedAt().AsTime().Format(time.RFC1123)
	}
	return datum, nil
}

func formatProtocol(protocol idpsession.BindingProtocol) string {
	switch protocol {
	case idpsession.BindingProtocol_BINDING_PROTOCOL_MCP:
		return "MCP"
	case idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER:
		return "Browser session"
	}
	return "Unknown"
}

func (s *Stateful) getLegacySSHSessionBindingInfo(ctx context.Context, userID string, redirectBase url.URL) ([]handlers.SessionBindingData, error) {
	pairs, err := s.codeReader.GetSessionBindingsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("could not fetch ssh bindings")
	}

	renderData := []handlers.SessionBindingData{}

	stableKeys := slices.Collect(maps.Keys(pairs))
	sort.Strings(stableKeys)

	for _, sessionBindingID := range stableKeys {
		p := pairs[sessionBindingID]
		redirectToSessB := redirectBase
		redirectToIdenB := redirectBase
		redirectToSessB.Path = "/.pomerium/session_binding/revoke"
		redirectToIdenB.Path = "/.pomerium/identity_binding/revoke"

		datum := handlers.SessionBindingData{
			SessionBindingID:         sessionBindingID,
			Protocol:                 p.SB.Protocol,
			Resource:                 "SSH key",
			InitiatedAt:              p.SB.IssuedAt.AsTime().Format(time.RFC1123),
			RevokeSessionBindingURL:  redirectToSessB.String(),
			HasIdentityBinding:       p.IB != nil,
			RevokeIdentityBindingURL: redirectToIdenB.String(),
		}
		if p.SB.Protocol == session.ProtocolSSH {
			sshDetails := &handlers.ProtocolDetailsSSH{
				FingerprintID: strings.TrimPrefix(sessionBindingID, "sshkey-SHA256:"),
			}
			if p.SB.Details != nil && p.SB.Details[session.DetailSourceAddr] != "" {
				sshDetails.SourceAddress = p.SB.Details[session.DetailSourceAddr]
			} else {
				sshDetails.SourceAddress = "Not recorded"
			}
			datum.DetailsSSH = sshDetails
			datum.ClientAddress = sshDetails.SourceAddress
		}

		if p.IB != nil {
			datum.ExpiresAt = "Until revoked"
		} else {
			datum.ExpiresAt = p.SB.ExpiresAt.AsTime().Format(time.RFC1123)
		}

		renderData = append(renderData, datum)
	}
	return renderData, nil
}

func (s *Stateful) redirectToSessionBindingInfo(w http.ResponseWriter, r *http.Request) {
	redirectTo := r.Referer()
	if redirectTo == "" {
		redirectURL := *r.URL
		redirectURL.Path = "/.pomerium/session_binding_info"
		redirectTo = redirectURL.String()
	}
	httputil.Redirect(w, r, redirectTo, http.StatusFound)
}

var errRevoke = httputil.NewError(http.StatusInternalServerError, fmt.Errorf("failed to revoke session binding"))

func (s *Stateful) RevokeSessionBinding(w http.ResponseWriter, r *http.Request, h *session.Handle) error {
	ctx := r.Context()
	if s.dataBrokerQuerier != nil {
		if q := s.dataBrokerQuerier(); q != nil {
			ctx = storage.WithQuerier(ctx, q)
		}
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	bindingID := r.Form.Get("sessionBindingID")
	protocol := r.Form.Get("protocol")

	if protocol == "ssh" {
		if err := s.codeRevoker.RevokeSessionBinding(ctx, code.BindingID(bindingID)); err != nil {
			return errRevoke
		}
		s.redirectToSessionBindingInfo(w, r)
		return nil
	}
	binding := &idpsession.Binding{}
	rec, err := s.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(binding),
		Id:   bindingID,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return httputil.NewError(http.StatusNotFound, fmt.Errorf("not found"))
		}
		return errRevoke
	}

	if err := rec.GetRecord().GetData().UnmarshalTo(binding); err != nil {
		return errRevoke
	}

	// FIXME: assumes idpsession id is userID. this is brittle. Perhaps a separate user_id field is good.
	if binding.GetIdpSessionId() != h.UserId {
		// do not leak details if someone has a uuid or is trying to guess a uuid.
		return httputil.NewError(http.StatusNotFound, fmt.Errorf("not found"))
	}
	binding.Revoke()

	s.dataBrokerClient.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(binding),
		},
	})

	if err := idpsession.RevokeBinding(ctx, s.dataBrokerClient, binding.GetId()); err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("internal error"))
	}

	s.redirectToSessionBindingInfo(w, r)
	return nil
}

// FIXME: hack
func formatBrowserUserAgent(userAgent string) string {
	if strings.TrimSpace(userAgent) == "" {
		return ""
	}

	browser := "Unknown browser"
	switch {
	case strings.Contains(userAgent, "EdgiOS/"), strings.Contains(userAgent, "EdgA/"), strings.Contains(userAgent, "Edg/"):
		browser = "Edge"
	case strings.Contains(userAgent, "OPiOS/"), strings.Contains(userAgent, "OPR/"):
		browser = "Opera"
	case strings.Contains(userAgent, "SamsungBrowser/"):
		browser = "Samsung"
	case strings.Contains(userAgent, "CriOS/"), strings.Contains(userAgent, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(userAgent, "FxiOS/"), strings.Contains(userAgent, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(userAgent, "Version/") && strings.Contains(userAgent, "Safari/"):
		browser = "Safari"
	}

	operatingSystem := "Unknown OS"
	switch {
	case strings.Contains(userAgent, "Android"):
		operatingSystem = "Android"
	case strings.Contains(userAgent, "iPad"):
		operatingSystem = "iPadOS"
	case strings.Contains(userAgent, "iPhone"), strings.Contains(userAgent, "iPod"):
		operatingSystem = "iOS"
	case strings.Contains(userAgent, "Windows"):
		operatingSystem = "Windows"
	case strings.Contains(userAgent, "CrOS"):
		operatingSystem = "ChromeOS"
	case strings.Contains(userAgent, "Macintosh"), strings.Contains(userAgent, "Mac OS X"):
		operatingSystem = "macOS"
	case strings.Contains(userAgent, "Linux"):
		operatingSystem = "Linux"
	}

	return browser + " on " + operatingSystem
}

func (s *Stateful) RevokeIdentityBinding(w http.ResponseWriter, r *http.Request, _ *session.Handle) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	sessionID := r.Form.Get("sessionBindingID")
	if err := s.codeRevoker.RevokeIdentityBinding(r.Context(), code.BindingID(sessionID)); err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("failed to revoke session"))
	}
	s.redirectToSessionBindingInfo(w, r)
	return nil
}

func browserBindingDetails(r *http.Request) map[string]string {
	details := make(map[string]string)
	if r == nil {
		return details
	}
	add := func(key, value string) {
		if value = strings.TrimSpace(value); value != "" {
			details[key] = value
		}
	}

	add("user-agent", r.UserAgent())
	add("client-ip", httputil.GetClientIP(r))
	add("x-forwarded-for", r.Header.Get("X-Forwarded-For"))
	add("x-forwarded-host", r.Header.Get("X-Forwarded-Host"))
	add("x-forwarded-proto", r.Header.Get("X-Forwarded-Proto"))

	return details
}

// PersistSession stores session and user data in the databroker.
func (s *Stateful) PersistSession(
	ctx context.Context,
	_ http.ResponseWriter,
	r *http.Request,
	h *session.Handle,
	claims identity.SessionClaims,
	accessToken *oauth2.Token,
) error {
	now := timeNow()
	sessionExpiry := timestamppb.New(now.Add(s.sessionDuration))

	sess := session.New(h.IdentityProviderId, h.Id)
	sess.UserId = h.UserId
	sess.IssuedAt = timestamppb.New(now)
	sess.AccessedAt = timestamppb.New(now)
	sess.ExpiresAt = sessionExpiry
	sess.OauthToken = manager.ToOAuthToken(accessToken)
	sess.Audience = h.Aud
	sess.SetRawIDToken(claims.RawIDToken)
	sess.AddClaims(claims.Flatten())

	u, _ := user.Get(ctx, s.dataBrokerClient, sess.GetUserId())
	if u == nil {
		// if no user exists yet, create a new one
		u = &user.User{
			Id: sess.GetUserId(),
		}
	}
	u.PopulateFromClaims(claims.Claims)
	idpClaims, err := structpb.NewStruct(claims.Claims)
	if err != nil {
		return fmt.Errorf("authenticate: error creating IDP session claims: %w", err)
	}
	idpSess := idpsession.NewFromSession(sess, idpClaims)
	bindingDetails := browserBindingDetails(r)

	// FIXME: hack
	log.Ctx(ctx).Warn().
		Str("idpsession-id", idpSess.GetId()).
		Str("session-id", sess.GetId()).
		Str("idp-id", idpSess.GetIdpId()).
		Str("hack-refresh-token", idpSess.GetOauthToken().GetRefreshToken()).
		Str("hack-access-token", idpSess.GetOauthToken().GetAccessToken()).
		Time("oauth-token-expires-at", idpSess.GetOauthToken().GetExpiresAt().AsTime()).
		Time("id-token-expires-at", idpSess.GetIdToken().GetExpiresAt().AsTime()).
		Msg("HACK authenticateflow/stateful: persisting idpsession tokens")

	records := []*databroker.Record{databroker.NewRecord(idpSess)}
	records = append(records,
		idpsession.NewBoundRecords(idpSess.GetId(), idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, bindingDetails, sess)...,
	)
	records = append(records,
		idpsession.NewBoundRecords(idpSess.GetId(), idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, bindingDetails, u)...,
	)
	res, err := s.dataBrokerClient.Put(ctx, &databroker.PutRequest{Records: records})
	if err != nil {
		return fmt.Errorf("authenticate: error saving browser identity records: %w", err)
	}
	h.DatabrokerServerVersion = new(res.GetServerVersion())
	for _, record := range res.GetRecords() {
		if record.GetType() == protoutil.GetTypeURL(sess) && record.GetId() == sess.GetId() {
			h.DatabrokerRecordVersion = new(record.GetVersion())
			break
		}
	}

	return nil
}

// GetUserInfoData returns user info data associated with the given request (if
// any).
func (s *Stateful) GetUserInfoData(
	r *http.Request, h *session.Handle,
) handlers.UserInfoData {
	var isImpersonated bool
	pbSession, err := session.Get(r.Context(), s.dataBrokerClient, h.Id)
	if sid := pbSession.GetImpersonateSessionId(); sid != "" {
		pbSession, err = session.Get(r.Context(), s.dataBrokerClient, sid)
		isImpersonated = true
	}
	if err != nil {
		pbSession = session.New(h.IdentityProviderId, h.Id)
	}

	pbUser, err := user.Get(r.Context(), s.dataBrokerClient, pbSession.GetUserId())
	if err != nil {
		pbUser = &user.User{
			Id: pbSession.GetUserId(),
		}
	}
	return SessionUserAsInfoData(pbSession, pbUser, isImpersonated)
}

func SessionUserAsInfoData(pbSession *session.Session, pbUser *user.User, isImpersonated bool) handlers.UserInfoData {
	return handlers.UserInfoData{
		IsImpersonated: isImpersonated,
		Session:        pbSession,
		User:           pbUser,
	}
}

func (s *Stateful) GetSessionAndUser(
	r *http.Request, h *session.Handle,
) (*session.Session, *user.User, bool) {
	var isImpersonated bool
	pbSession, err := session.Get(r.Context(), s.dataBrokerClient, h.Id)
	if sid := pbSession.GetImpersonateSessionId(); sid != "" {
		pbSession, err = session.Get(r.Context(), s.dataBrokerClient, sid)
		isImpersonated = true
	}
	if err != nil {
		pbSession = session.New(h.IdentityProviderId, h.Id)
	}

	pbUser, err := user.Get(r.Context(), s.dataBrokerClient, pbSession.GetUserId())
	if err != nil {
		pbUser = &user.User{
			Id: pbSession.GetUserId(),
		}
	}
	return pbSession, pbUser, isImpersonated
}

// RevokeSession revokes the session associated with the provided request,
// returning the ID token from the revoked session.
func (s *Stateful) RevokeSession(
	ctx context.Context,
	_ *http.Request,
	authenticator identity.Authenticator,
	h *session.Handle,
) string {
	if h == nil {
		return ""
	}

	// Note: session.Delete() cannot be used safely, because the identity
	// manager expects to be able to read both session ID and user ID from
	// deleted session records. Instead, we match the behavior used in the
	// identity manager itself: fetch the existing databroker session record,
	// explicitly set the DeletedAt timestamp, and Put() that record back.

	record, err := storage.DeleteDataBrokerRecord(ctx, s.dataBrokerClient, grpcutil.GetTypeURL(new(session.Session)), h.Id)
	if err != nil {
		err = fmt.Errorf("couldn't get session to be revoked: %w", err)
		log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to revoke access token")
		return ""
	} else if record == nil {
		// session doesn't exist
		return ""
	}

	var sess session.Session
	if err := record.GetData().UnmarshalTo(&sess); err != nil {
		err = fmt.Errorf("couldn't unmarshal data of session to be revoked: %w", err)
		log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to revoke access token")
		return ""
	}

	var rawIDToken string
	if sess.OauthToken != nil {
		rawIDToken = sess.GetIdToken().GetRaw()
		if err := authenticator.Revoke(ctx, manager.FromOAuthToken(sess.OauthToken)); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("authenticate: failed to revoke access token")
		}
	}
	return rawIDToken
}

// VerifySession checks that an existing session is still valid.
func (s *Stateful) VerifySession(
	ctx context.Context, _ *http.Request, h *session.Handle,
) error {
	sess, err := session.Get(ctx, s.dataBrokerClient, h.Id)
	if err != nil {
		return fmt.Errorf("session not found in databroker: %w", err)
	}
	return sess.Validate()
}

func (s *Stateful) sessionExpiresAt(ctx context.Context, h *session.Handle) (*time.Time, error) {
	sess, err := session.Get(ctx, s.dataBrokerClient, h.Id)
	if err != nil {
		return nil, fmt.Errorf("session not found in databroker: %w", err)
	}

	if expiresAt := sess.GetExpiresAt(); expiresAt != nil {
		t := expiresAt.AsTime()
		return &t, nil
	}
	if expiresAt := sess.GetOauthToken().GetExpiresAt(); expiresAt != nil {
		t := expiresAt.AsTime()
		return &t, nil
	}
	return nil, nil
}

// LogAuthenticateEvent is a no-op for the stateful authentication flow.
func (s *Stateful) LogAuthenticateEvent(*http.Request) {}

// AuthenticateSignInURL returns a URL to redirect the user to the authenticate
// domain.
func (s *Stateful) AuthenticateSignInURL(
	ctx context.Context,
	queryParams url.Values,
	redirectURL *url.URL,
	idpID string,
	additionalHosts []string,
) (string, error) {
	signinURL := s.authenticateURL.ResolveReference(&url.URL{
		Path: endpoints.PathPomeriumSignIn,
	})

	if queryParams == nil {
		queryParams = url.Values{}
	}
	queryParams.Set(urlutil.QueryRedirectURI, redirectURL.String())
	queryParams.Set(urlutil.QueryIdentityProviderID, idpID)
	if len(additionalHosts) > 0 {
		queryParams.Set(urlutil.QueryAdditionalHosts, strings.Join(additionalHosts, ","))
	}
	otel.GetTextMapPropagator().Inject(ctx, trace.PomeriumURLQueryCarrier(queryParams))
	signinURL.RawQuery = queryParams.Encode()
	redirectTo := urlutil.NewSignedURL(s.sharedKey, signinURL).String()

	return redirectTo, nil
}

// GetIdentityProviderIDForURLValues returns the identity provider ID
// associated with the given URL values.
func (s *Stateful) GetIdentityProviderIDForURLValues(vs url.Values) string {
	if id := vs.Get(urlutil.QueryIdentityProviderID); id != "" {
		return id
	}
	return s.defaultIdentityProviderID
}

// Callback handles a redirect to a route domain once signed in.
func (s *Stateful) Callback(w http.ResponseWriter, r *http.Request) error {
	if err := s.VerifySignature(r); err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	redirectURLString := r.FormValue(urlutil.QueryRedirectURI)
	encryptedSession := r.FormValue(urlutil.QuerySessionEncrypted)

	redirectURL, err := urlutil.ParseAndValidateURL(redirectURLString)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, err)
	}

	encryptedJWT, err := base64.URLEncoding.DecodeString(encryptedSession)
	if err != nil {
		return fmt.Errorf("proxy: malfromed callback token: %w", err)
	}

	rawJWT, err := cryptutil.Decrypt(s.sharedCipher, encryptedJWT, nil)
	if err != nil {
		return fmt.Errorf("proxy: callback token decrypt error: %w", err)
	}

	// save the session handle
	if err = s.sessionStore.WriteSessionHandleJWT(w, rawJWT); err != nil {
		return httputil.NewError(http.StatusInternalServerError, fmt.Errorf("proxy: error saving session handle: %w", err))
	}

	// if programmatic, encode the session jwt as a query param
	if isProgrammatic := r.FormValue(urlutil.QueryIsProgrammatic); isProgrammatic == "true" {
		q := redirectURL.Query()
		q.Set(urlutil.QueryPomeriumJWT, string(rawJWT))
		redirectURL.RawQuery = q.Encode()
	}

	// Redirect chaining for multi-domain login.
	additionalHosts := r.URL.Query().Get(urlutil.QueryAdditionalHosts)
	if additionalHosts != "" {
		nextHops := strings.Split(additionalHosts, ",")
		log.Ctx(r.Context()).Debug().Strs("next-hops", nextHops).Msg("multi-domain login callback")

		callbackURL, err := urlutil.GetCallbackURL(r, encryptedSession, nextHops[1:])
		if err != nil {
			return httputil.NewError(http.StatusInternalServerError,
				fmt.Errorf("proxy: couldn't get next hop callback URL: %w", err))
		}
		callbackURL.Host = nextHops[0]
		signedCallbackURL := urlutil.NewSignedURL(s.sharedKey, callbackURL)
		httputil.Redirect(w, r, signedCallbackURL.String(), http.StatusFound)
		return nil
	}

	// redirect
	httputil.Redirect(w, r, redirectURL.String(), http.StatusFound)
	return nil
}

type SSHSignInHandler interface {
	SuccessRedirect(w http.ResponseWriter, r *http.Request, data SignSuccessRawData)
}

type SignSuccessRawData struct {
	Session *session.Session
	User    *user.User
	Sbr     *session.SessionBindingRequest
	// ExpiresAt may be nil
	ExpiresAt *time.Time
}

type defaultSignInHandler struct{}

var _ SSHSignInHandler = (*defaultSignInHandler)(nil)

func (d *defaultSignInHandler) SuccessRedirect(
	w http.ResponseWriter,
	r *http.Request,
	data SignSuccessRawData,
) {
	handlers.SignInSuccess(handlers.SignInSuccessData{
		UserInfoData: SessionUserAsInfoData(data.Session, data.User, false),
		ExpiresAt:    data.ExpiresAt,
		Protocol:     data.Sbr.Protocol,
	}).ServeHTTP(w, r)
}
