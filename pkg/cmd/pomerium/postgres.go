package pomerium

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/postgresproxy"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type postgresService struct {
	current       atomic.Pointer[config.Config]
	downstreamTLS atomic.Pointer[tls.Config]
	listener      net.Listener
	listenAddr    string
	server        *postgresproxy.Server
	stopMu        sync.Mutex
	stop          context.CancelFunc
}

func setupPostgres(ctx context.Context, src config.Source, authz *authorize.Authorize) (*postgresService, error) {
	cfg := src.GetConfig()
	if !shouldStartPostgres(cfg.Options) {
		return nil, nil
	}
	if authz == nil {
		return nil, errors.New("native postgres requires the authorize service in this preview")
	}
	ln, err := net.Listen("tcp", cfg.Options.PostgresAddr)
	if err != nil {
		return nil, fmt.Errorf("error creating postgres listener: %w", err)
	}

	tlsCfg, err := postgresDownstreamTLSConfig(ctx, cfg)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	svc := &postgresService{listener: ln, listenAddr: cfg.Options.PostgresAddr}
	svc.current.Store(cfg)
	svc.downstreamTLS.Store(tlsCfg)
	src.OnConfigChange(ctx, func(_ context.Context, cfg *config.Config) {
		if !shouldStartPostgres(cfg.Options) || cfg.Options.PostgresAddr != svc.listenAddr {
			log.Ctx(ctx).Info().Msg("stopping native postgres listener after config change; restart required to re-enable")
			svc.Stop()
			return
		}
		tlsCfg, err := postgresDownstreamTLSConfig(ctx, cfg)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("postgres: error updating downstream TLS config")
			return
		}
		svc.current.Store(cfg)
		svc.downstreamTLS.Store(tlsCfg)
	})

	adapter := &postgresCoreAdapter{
		current: &svc.current,
		authz:   authz,
	}
	svc.server = &postgresproxy.Server{
		DownstreamTLS: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
				tlsCfg := svc.downstreamTLS.Load()
				if tlsCfg == nil {
					return nil, errors.New("postgres downstream TLS config is not ready")
				}
				return tlsCfg.Clone(), nil
			},
		},
		ReauthorizeInterval: time.Minute,
		Identity:            adapter,
		Policy:              adapter,
		UpstreamResolver:    adapter,
	}
	return svc, nil
}

func shouldStartPostgres(options *config.Options) bool {
	return options != nil &&
		options.PostgresAddr != "" &&
		options.IsRuntimeFlagSet(config.RuntimeFlagPostgres)
}

func (svc *postgresService) Run(ctx context.Context) error {
	if svc == nil {
		return nil
	}
	runCtx, stop := context.WithCancel(ctx)
	svc.stopMu.Lock()
	svc.stop = stop
	svc.stopMu.Unlock()
	defer func() {
		stop()
		svc.stopMu.Lock()
		svc.stop = nil
		svc.stopMu.Unlock()
	}()
	log.Ctx(ctx).Info().Str("addr", svc.listener.Addr().String()).Msg("starting native postgres listener")
	err := svc.server.Serve(runCtx, svc.listener)
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (svc *postgresService) Stop() {
	if svc == nil {
		return
	}
	svc.stopMu.Lock()
	stop := svc.stop
	svc.stopMu.Unlock()
	if stop != nil {
		stop()
		return
	}
	_ = svc.listener.Close()
}

func postgresDownstreamTLSConfig(ctx context.Context, cfg *config.Config) (*tls.Config, error) {
	certs, err := postgresCertificates(cfg)
	if err != nil {
		return nil, err
	}
	clientCA := postgresClientCABundle(ctx, cfg)
	if len(clientCA) == 0 {
		return nil, errors.New("postgres downstream client CA is required")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCA) {
		return nil, errors.New("postgres downstream client CA bundle is invalid")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: certs,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

func postgresCertificates(cfg *config.Config) ([]tls.Certificate, error) {
	certs, err := cfg.AllCertificates()
	if err != nil {
		return nil, fmt.Errorf("postgres certificates: %w", err)
	}
	if cfg.Options.DeriveInternalDomainCert != nil || len(certs) == 0 {
		cert, err := cfg.GenerateCatchAllCertificate()
		if err != nil {
			return nil, fmt.Errorf("postgres fallback certificate: %w", err)
		}
		certs = append(certs, *cert)
	}
	return certs, nil
}

func postgresClientCABundle(ctx context.Context, cfg *config.Config) []byte {
	var bundle strings.Builder
	if ca, _ := cfg.Options.DownstreamMTLS.GetCA(); len(ca) > 0 {
		addPostgresClientCA(&bundle, ca)
	}
	for p := range cfg.Options.GetAllPolicies() {
		if !p.IsPostgres() {
			continue
		}
		if p.TLSDownstreamClientCA == "" {
			continue
		}
		ca, err := base64.StdEncoding.DecodeString(p.TLSDownstreamClientCA)
		if err != nil {
			log.Ctx(ctx).Error().Stringer("policy", p).Err(err).Msg("invalid postgres client CA")
			continue
		}
		addPostgresClientCA(&bundle, ca)
	}
	return []byte(bundle.String())
}

func addPostgresClientCA(bundle *strings.Builder, ca []byte) {
	if len(ca) == 0 {
		return
	}
	_, _ = bundle.Write(ca)
	if ca[len(ca)-1] != '\n' {
		_ = bundle.WriteByte('\n')
	}
}

func verifyPostgresClientCertificateForRoute(options *config.Options, route *config.Policy, certPEM string, now time.Time) error {
	var caPEM []byte
	if route.TLSDownstreamClientCA != "" {
		var err error
		caPEM, err = base64.StdEncoding.DecodeString(route.TLSDownstreamClientCA)
		if err != nil {
			return fmt.Errorf("postgres route client CA is invalid: %w", err)
		}
	} else if options != nil {
		ca, err := options.DownstreamMTLS.GetCA()
		if err != nil {
			return fmt.Errorf("postgres downstream client CA is invalid: %w", err)
		}
		caPEM = ca
	}
	if len(caPEM) == 0 {
		return errors.New("postgres route requires a downstream client CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("postgres route client CA is invalid")
	}
	certs, err := parseCertificateChainPEM([]byte(certPEM))
	if err != nil {
		return fmt.Errorf("postgres client certificate is invalid: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err = certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("postgres client certificate is not trusted for route: %w", err)
	}
	return nil
}

func parseCertificateChainPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}
	return certs, nil
}

type postgresCoreAdapter struct {
	current *atomic.Pointer[config.Config]
	authz   *authorize.Authorize
}

func (a *postgresCoreAdapter) Authenticate(ctx context.Context, req postgresproxy.AuthRequest) (*postgresproxy.Session, error) {
	route := a.current.Load().Options.GetRouteForPostgresHostname(req.ServerName)
	if route == nil {
		return nil, fmt.Errorf("postgres route not found for SNI %q", req.ServerName)
	}
	if !route.IsPostgresUpstream() {
		return nil, errors.New("postgres route requires a postgres upstream")
	}
	certPEM := req.ClientCertChainPEM
	if certPEM == "" {
		certPEM = req.ClientCertPEM
	}
	if err := verifyPostgresClientCertificateForRoute(a.current.Load().Options, route, certPEM, time.Now()); err != nil {
		return nil, err
	}
	bindingID, binding, webSession, err := a.resolveSessionBindingFromFingerprint(ctx, req.ClientCertSHA256)
	if err != nil {
		return nil, err
	}
	routeID, _ := route.RouteID()
	return &postgresproxy.Session{
		ID:                postgresConnectionID(req.ClientCertSHA256),
		PomeriumSessionID: binding.SessionId,
		SessionBindingID:  bindingID,
		UserID:            binding.UserId,
		RouteID:           routeID,
		Hostname:          req.ServerName,
		Database:          req.Database,
		DatabaseUser:      req.Username,
		ApplicationName:   req.ApplicationName,
		ClientAddr:        req.ClientAddr.String(),
		ClientCertSHA256:  req.ClientCertSHA256,
		ClientCertPEM:     req.ClientCertPEM,
		StartedAt:         time.Now(),
	}, postgresSessionStillValid(webSession)
}

func (a *postgresCoreAdapter) Reauthorize(ctx context.Context, session *postgresproxy.Session) error {
	_, binding, webSession, err := a.resolveSessionBinding(ctx, session.SessionBindingID)
	if err != nil {
		return err
	}
	if binding.SessionId != session.PomeriumSessionID || binding.UserId != session.UserID {
		return errors.New("postgres session binding no longer matches the connection")
	}
	if err := postgresSessionStillValid(webSession); err != nil {
		return err
	}
	if _, err := a.routeForSession(session); err != nil {
		return err
	}
	return a.AuthorizeSession(ctx, session)
}

func (a *postgresCoreAdapter) UpstreamCredentials(ctx context.Context, session *postgresproxy.Session) (*postgresproxy.UpstreamCredentials, error) {
	route, err := a.routeForSession(session)
	if err != nil {
		return nil, err
	}
	upstream := route.To[0].URL
	username := upstream.User.Username()
	password, ok := upstream.User.Password()
	if username == "" || !ok || password == "" {
		return nil, errors.New("postgres upstream credentials are required")
	}
	database := strings.TrimPrefix(upstream.Path, "/")
	if database == "" {
		database = session.Database
	}
	return &postgresproxy.UpstreamCredentials{
		Username: username,
		Password: password,
		Database: database,
	}, nil
}

func (a *postgresCoreAdapter) AuthorizeSession(ctx context.Context, session *postgresproxy.Session) error {
	res, err := a.authz.EvaluatePostgresSession(ctx, postgresRequestFromSession(session, "", ""))
	if err != nil {
		return err
	}
	if !postgresEvaluationAllowed(res) {
		return fmt.Errorf("postgres session denied by policy: %s", postgresEvaluationReason(res))
	}
	return nil
}

func (a *postgresCoreAdapter) AuthorizeQuery(ctx context.Context, req postgresproxy.QueryRequest) (*postgresproxy.Decision, error) {
	res, err := a.authz.EvaluatePostgresQuery(ctx, postgresRequestFromSession(req.Session, req.StatementClass, string(req.Protocol)))
	if err != nil {
		return nil, err
	}
	if !postgresEvaluationAllowed(res) {
		return &postgresproxy.Decision{
			Action: postgresproxy.DecisionDeny,
			Reason: postgresEvaluationReason(res),
		}, nil
	}
	return &postgresproxy.Decision{Action: postgresproxy.DecisionAllow}, nil
}

func (a *postgresCoreAdapter) ResolveUpstream(ctx context.Context, session *postgresproxy.Session) (*postgresproxy.UpstreamTarget, error) {
	route, err := a.routeForSession(session)
	if err != nil {
		return nil, err
	}
	upstream := route.To[0].URL
	addr := upstream.Host
	if addr == "" {
		return nil, errors.New("postgres upstream host is required")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(upstream.Hostname(), "5432")
	}
	tlsConfig, err := postgresUpstreamTLSConfig(a.current.Load().Options, route, &upstream)
	if err != nil {
		return nil, err
	}
	return &postgresproxy.UpstreamTarget{
		Addr:      addr,
		TLSConfig: tlsConfig,
	}, nil
}

func (a *postgresCoreAdapter) routeForSession(session *postgresproxy.Session) (*config.Policy, error) {
	if session == nil {
		return nil, errors.New("postgres session is required")
	}
	route := a.current.Load().Options.GetRouteForPostgresHostname(session.Hostname)
	if route == nil {
		return nil, fmt.Errorf("postgres route not found for SNI %q", session.Hostname)
	}
	if !route.IsPostgresUpstream() {
		return nil, errors.New("postgres route requires a postgres upstream")
	}
	if session.RouteID != "" {
		routeID, _ := route.RouteID()
		if routeID != "" && routeID != session.RouteID {
			return nil, errors.New("postgres route changed during session")
		}
	}
	return route, nil
}

func postgresRequestFromSession(session *postgresproxy.Session, statementClass, queryProtocol string) authorize.PostgresRequest {
	if session == nil {
		return authorize.PostgresRequest{}
	}
	return authorize.PostgresRequest{
		Hostname:         session.Hostname,
		Database:         session.Database,
		Username:         session.DatabaseUser,
		ApplicationName:  session.ApplicationName,
		StatementClass:   statementClass,
		QueryProtocol:    queryProtocol,
		SessionID:        session.PomeriumSessionID,
		SessionBindingID: session.SessionBindingID,
		SourceAddress:    postgresSourceAddress(session.ClientAddr),
		ClientCertPEM:    session.ClientCertPEM,
	}
}

func (a *postgresCoreAdapter) resolveSessionBindingFromFingerprint(ctx context.Context, fingerprintHex string) (string, *sessionpb.SessionBinding, *sessionpb.Session, error) {
	fingerprint, err := hex.DecodeString(fingerprintHex)
	if err != nil {
		return "", nil, nil, fmt.Errorf("postgres client certificate fingerprint is invalid: %w", err)
	}
	bindingID, err := postgresSessionBindingIDFromFingerprint(fingerprint)
	if err != nil {
		return "", nil, nil, err
	}
	return a.resolveSessionBinding(ctx, bindingID)
}

func (a *postgresCoreAdapter) resolveSessionBinding(ctx context.Context, bindingID string) (string, *sessionpb.SessionBinding, *sessionpb.Session, error) {
	if bindingID == "" {
		return "", nil, nil, errors.New("postgres session binding is required")
	}
	client := a.authz.GetDataBrokerServiceClient()
	resp, err := client.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(sessionpb.SessionBinding)),
		Id:   bindingID,
	})
	if err != nil {
		return "", nil, nil, err
	}
	if resp.GetRecord().GetDeletedAt() != nil {
		return "", nil, nil, errors.New("postgres session binding deleted")
	}
	var binding sessionpb.SessionBinding
	if err := resp.GetRecord().GetData().UnmarshalTo(&binding); err != nil {
		return "", nil, nil, err
	}
	if binding.Protocol != sessionpb.ProtocolPostgres {
		return "", nil, nil, errors.New("postgres session binding has invalid protocol")
	}
	if expiresAt := binding.GetExpiresAt(); expiresAt != nil && expiresAt.AsTime().Before(time.Now()) {
		return "", nil, nil, errors.New("postgres session binding expired")
	}

	sessionResp, err := client.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(sessionpb.Session)),
		Id:   binding.SessionId,
	})
	if err != nil {
		return "", nil, nil, err
	}
	if sessionResp.GetRecord().GetDeletedAt() != nil {
		return "", nil, nil, errors.New("postgres web session deleted")
	}
	var webSession sessionpb.Session
	if err := sessionResp.GetRecord().GetData().UnmarshalTo(&webSession); err != nil {
		return "", nil, nil, err
	}
	return bindingID, &binding, &webSession, nil
}

func postgresSessionBindingIDFromFingerprint(sha256Fingerprint []byte) (string, error) {
	if len(sha256Fingerprint) != sha256.Size {
		return "", errors.New("invalid postgres client certificate fingerprint")
	}
	return "postgrescert-SHA256:" + base64.RawStdEncoding.EncodeToString(sha256Fingerprint), nil
}

func postgresSessionStillValid(s *sessionpb.Session) error {
	if s == nil {
		return errors.New("postgres web session missing")
	}
	if expiresAt := s.GetExpiresAt(); expiresAt != nil && expiresAt.AsTime().Before(time.Now()) {
		return errors.New("postgres web session expired")
	}
	return nil
}

func postgresConnectionID(fingerprintHex string) string {
	if len(fingerprintHex) > 16 {
		fingerprintHex = fingerprintHex[:16]
	}
	return fmt.Sprintf("postgres-%s-%d", fingerprintHex, time.Now().UnixNano())
}

func postgresSourceAddress(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return addr
}

func postgresEvaluationAllowed(res *evaluator.Result) bool {
	return res != nil && res.Allow.Value && !res.Deny.Value
}

func postgresEvaluationReason(res *evaluator.Result) string {
	if res == nil {
		return "policy returned no result"
	}
	if res.Deny.Value {
		if reasons := res.Deny.Reasons.Strings(); len(reasons) > 0 {
			return strings.Join(reasons, ", ")
		}
		return "deny matched"
	}
	if !res.Allow.Value {
		if reasons := res.Allow.Reasons.Strings(); len(reasons) > 0 {
			return strings.Join(reasons, ", ")
		}
		return "allow did not match"
	}
	return ""
}

func postgresUpstreamTLSConfig(options *config.Options, policy *config.Policy, upstream *url.URL) (*tls.Config, error) {
	var tlsConfig tls.Config
	sslmode := ""
	if upstream != nil {
		sslmode = upstream.Query().Get("sslmode")
	}
	switch sslmode {
	case "disable":
		return nil, nil
	case "", "verify-full":
	case "require":
		// Match libpq sslmode=require: encrypt the upstream hop without
		// verifying the server certificate. The default empty sslmode is
		// stricter and verifies the server name.
		tlsConfig.InsecureSkipVerify = true
	default:
		return nil, fmt.Errorf("postgres upstream sslmode %q is not supported", sslmode)
	}
	if policy.TLSSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	if options.CA != "" || options.CAFile != "" {
		rootCAs, err := cryptutil.GetCertPool(options.CA, options.CAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = rootCAs
	}
	if policy.TLSCustomCA != "" || policy.TLSCustomCAFile != "" {
		rootCAs, err := cryptutil.GetCertPool(policy.TLSCustomCA, policy.TLSCustomCAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = rootCAs
	}
	if policy.ClientCertificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*policy.ClientCertificate}
	}
	if policy.TLSServerName != "" {
		tlsConfig.ServerName = policy.TLSServerName
	}
	if policy.TLSUpstreamServerName != "" {
		tlsConfig.ServerName = policy.TLSUpstreamServerName
	}
	if tlsConfig.ServerName == "" && upstream != nil {
		tlsConfig.ServerName = upstream.Hostname()
	}
	tlsConfig.MinVersion = tls.VersionTLS12
	return &tlsConfig, nil
}
