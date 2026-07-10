package pomerium

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/postgresidentity"
	"github.com/pomerium/pomerium/internal/postgresproxy"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/enterprise/capability"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/health"
)

type postgresRuntimeSnapshot struct {
	configGeneration         *config.Config
	downstreamTLS            *tls.Config
	managedPostgresAuthority capability.ManagedPostgresAuthority
	routes                   map[string]*postgresRuntimeRoute
}

type postgresRuntimeRoute struct {
	hostname                   string
	revision                   string
	policyRevision             string
	expectedIdentityProviderID string
	credentials                postgresproxy.UpstreamCredentials
	upstream                   postgresproxy.UpstreamTarget
}

type postgresConfigUpdate struct {
	ctx context.Context
}

type postgresListenerGeneration struct {
	configuredAddr string
	listener       net.Listener
	cancel         context.CancelFunc
	done           <-chan error
}

type postgresReadyListener struct {
	net.Listener
	ready chan struct{}
	once  sync.Once
}

func (l *postgresReadyListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.ready) })
	return l.Listener.Accept()
}

type postgresService struct {
	runtime atomic.Pointer[postgresRuntimeSnapshot]
	server  *postgresproxy.Server
	source  config.Source

	updatesMu  sync.Mutex
	updates    chan postgresConfigUpdate
	closed     atomic.Bool
	stateMu    sync.Mutex
	listener   net.Listener // current generation; retained for integration tests
	listenAddr string
	stopMu     sync.Mutex
	stop       context.CancelFunc

	listen            func(context.Context, string, string) (net.Listener, error)
	after             func(time.Duration) <-chan time.Time
	reportRunning     func()
	reportError       func(error)
	reportTerminating func()
}

func setupPostgres(
	ctx context.Context,
	src config.Source,
	authz *authorize.Authorize,
	managedVerifier ...capability.ManagedPostgresVerifier,
) (*postgresService, error) {
	cfg := src.GetConfig()
	if authz == nil {
		if shouldStartPostgres(cfg.Options) {
			return nil, errors.New("native postgres requires the authorize service")
		}
		return nil, nil
	}
	lc := new(net.ListenConfig)
	svc := &postgresService{
		updates:       make(chan postgresConfigUpdate, 1),
		source:        src,
		listen:        lc.Listen,
		after:         time.After,
		reportRunning: func() { health.ReportRunning(health.PostgresListener) },
		reportError: func(error) {
			health.ReportError(health.PostgresListener, errors.New("postgres listener unavailable"))
		},
		reportTerminating: func() { health.ReportTerminating(health.PostgresListener) },
	}

	verifier := capability.ManagedPostgresVerifier(capability.NewConsumer(authz))
	if len(managedVerifier) > 0 && managedVerifier[0] != nil {
		verifier = managedVerifier[0]
	}
	adapter := &postgresCoreAdapter{
		runtime:         &svc.runtime,
		authz:           authz,
		managedPostgres: verifier,
	}
	svc.server = &postgresproxy.Server{
		DownstreamTLS: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
				snapshot := svc.runtime.Load()
				if snapshot == nil || snapshot.downstreamTLS == nil {
					return nil, errors.New("postgres downstream TLS config is not ready")
				}
				return snapshot.downstreamTLS.Clone(), nil
			},
		},
		ReauthorizeInterval: time.Minute,
		MaxConnections:      1024,
		Identity:            adapter,
		Policy:              adapter,
		UpstreamResolver:    adapter,
	}
	src.OnConfigChange(ctx, func(updateCtx context.Context, _ *config.Config) {
		svc.enqueue(postgresConfigUpdate{ctx: context.WithoutCancel(updateCtx)})
	})
	// Updates are triggers, not config payloads. Reconciliation reads the current
	// source value, so a callback racing this initial trigger cannot be overwritten
	// by the configuration captured at function entry.
	svc.enqueue(postgresConfigUpdate{ctx: context.WithoutCancel(ctx)})
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
		svc.updatesMu.Lock()
		svc.closed.Store(true)
		svc.updatesMu.Unlock()
		svc.stopMu.Lock()
		svc.stop = nil
		svc.stopMu.Unlock()
		svc.runtime.Store(nil)
		svc.reportTerminating()
	}()

	var desired postgresConfigUpdate
	var generation *postgresListenerGeneration
	var generationDone <-chan error
	var retry <-chan time.Time
	retryDelay := time.Second

	stopGeneration := func() {
		if generation == nil {
			return
		}
		generation.cancel()
		_ = generation.listener.Close()
		<-generation.done
		generation = nil
		generationDone = nil
		svc.setListener(nil, "")
	}
	defer stopGeneration()

	scheduleRetry := func() {
		if retry == nil {
			retry = svc.after(retryDelay)
			if retryDelay < 30*time.Second {
				retryDelay *= 2
				if retryDelay > 30*time.Second {
					retryDelay = 30 * time.Second
				}
			}
		}
	}

	reconcile := func() {
		cfg := svc.source.GetConfig()
		if cfg == nil || !shouldStartPostgres(cfg.Options) {
			stopGeneration()
			svc.runtime.Store(nil)
			svc.reportTerminating()
			retry = nil
			return
		}
		managedPostgresAuthority, sharedKey, authorityErr := postgresManagedPostgresAuthority(cfg)
		handleReconcileFailure := func() {
			current := svc.runtime.Load()
			if generation != nil && (authorityErr != nil || current == nil ||
				!current.managedPostgresAuthority.Equal(managedPostgresAuthority)) {
				// Clear authority before closing the serving generation so in-flight
				// authentication and reauthorization fail closed immediately.
				svc.runtime.Store(nil)
				stopGeneration()
			}
			scheduleRetry()
		}
		if authorityErr != nil {
			log.Ctx(desired.ctx).Error().Err(authorityErr).Msg("postgres: managed capability authority unavailable")
			svc.reportError(authorityErr)
			handleReconcileFailure()
			return
		}
		snapshot, err := newPostgresRuntimeSnapshot(cfg, managedPostgresAuthority, sharedKey)
		if err != nil {
			log.Ctx(desired.ctx).Error().Err(err).Msg("postgres: runtime configuration unavailable")
			svc.reportError(err)
			handleReconcileFailure()
			return
		}
		if generation != nil && generation.configuredAddr == cfg.Options.PostgresAddr {
			svc.runtime.Store(snapshot)
			svc.reportRunning()
			retry = nil
			retryDelay = time.Second
			return
		}
		ln, err := svc.listen(runCtx, "tcp", cfg.Options.PostgresAddr)
		if err != nil {
			log.Ctx(desired.ctx).Error().Err(err).Msg("postgres: listener unavailable")
			svc.reportError(err)
			handleReconcileFailure()
			return
		}
		serveCtx, cancelServe := context.WithCancel(runCtx)
		done := make(chan error, 1)
		newGeneration := &postgresListenerGeneration{
			configuredAddr: cfg.Options.PostgresAddr,
			listener:       ln,
			cancel:         cancelServe,
			done:           done,
		}
		oldGeneration := generation
		generation = newGeneration
		generationDone = done
		svc.runtime.Store(snapshot)
		svc.setListener(ln, cfg.Options.PostgresAddr)
		ready := make(chan struct{})
		serveListener := &postgresReadyListener{Listener: ln, ready: ready}
		go func() { done <- svc.server.Serve(serveCtx, serveListener) }()
		<-ready
		log.Ctx(desired.ctx).Info().Str("addr", ln.Addr().String()).Msg("starting native postgres listener")
		svc.reportRunning()
		retry = nil
		retryDelay = time.Second
		if oldGeneration != nil {
			oldGeneration.cancel()
			_ = oldGeneration.listener.Close()
			<-oldGeneration.done
		}
	}

	for {
		select {
		case <-runCtx.Done():
			return nil
		case update := <-svc.updates:
			desired = update
			retry = nil
			retryDelay = time.Second
			reconcile()
		case <-retry:
			retry = nil
			reconcile()
		case err := <-generationDone:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				log.Ctx(desired.ctx).Error().Err(err).Msg("postgres: listener stopped unexpectedly")
			}
			generation = nil
			generationDone = nil
			svc.runtime.Store(nil)
			svc.setListener(nil, "")
			svc.reportError(err)
			scheduleRetry()
		}
	}
}

func (svc *postgresService) enqueue(update postgresConfigUpdate) {
	svc.updatesMu.Lock()
	defer svc.updatesMu.Unlock()
	if svc.closed.Load() {
		return
	}
	select {
	case <-svc.updates:
	default:
	}
	svc.updates <- update
}

func (svc *postgresService) setListener(listener net.Listener, addr string) {
	svc.stateMu.Lock()
	svc.listener = listener
	svc.listenAddr = addr
	svc.stateMu.Unlock()
}

func (svc *postgresService) currentListener() net.Listener {
	svc.stateMu.Lock()
	defer svc.stateMu.Unlock()
	return svc.listener
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
	svc.stateMu.Lock()
	listener := svc.listener
	svc.stateMu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
}

func newPostgresRuntimeSnapshot(
	cfg *config.Config,
	authority capability.ManagedPostgresAuthority,
	sharedKey []byte,
) (*postgresRuntimeSnapshot, error) {
	if cfg == nil || cfg.Options == nil {
		return nil, errors.New("postgres runtime configuration is incomplete")
	}
	tlsCfg, err := postgresDownstreamTLSConfig(cfg, sharedKey)
	if err != nil {
		return nil, err
	}
	options := *cfg.Options
	clientSecret, err := cfg.Options.GetClientSecret()
	if err != nil {
		return nil, errors.New("postgres identity provider secret is unavailable")
	}
	options.ClientSecret = clientSecret
	options.ClientSecretFile = ""
	globalCA, err := materializePostgresCA(cfg.Options.CA, cfg.Options.CAFile)
	if err != nil {
		return nil, fmt.Errorf("postgres global upstream CA: %w", err)
	}
	if len(globalCA) > 0 {
		options.CA = base64.StdEncoding.EncodeToString(globalCA)
	}
	options.CAFile = ""

	routes := make(map[string]*postgresRuntimeRoute)
	for policy := range cfg.Options.GetAllPolicies() {
		if !policy.IsPostgres() {
			continue
		}
		route, err := materializePostgresRoute(&options, policy, globalCA)
		if err != nil {
			return nil, err
		}
		if _, ok := routes[route.hostname]; ok {
			return nil, fmt.Errorf("postgres route hostname %q is duplicated", route.hostname)
		}
		routes[route.hostname] = route
	}
	return &postgresRuntimeSnapshot{
		configGeneration:         cfg,
		downstreamTLS:            tlsCfg,
		managedPostgresAuthority: authority,
		routes:                   routes,
	}, nil
}

func postgresDownstreamTLSConfig(cfg *config.Config, sharedKey []byte) (*tls.Config, error) {
	certs, err := postgresCertificates(cfg, sharedKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: certs,
		// The application validates the constrained self-signed certificate
		// against its live SessionBinding. RequestClientCert is intentional:
		// it also permits the CLI's initial server-trust probe without a cert.
		ClientAuth: tls.RequestClientCert,
	}, nil
}

func postgresCertificates(cfg *config.Config, sharedKey []byte) ([]tls.Certificate, error) {
	certs, err := cfg.AllCertificates()
	if err != nil {
		return nil, fmt.Errorf("postgres certificates: %w", err)
	}
	if cfg.Options.DeriveInternalDomainCert != nil || len(certs) == 0 {
		cert, err := cryptutil.GenerateCertificate(sharedKey, "*")
		if err != nil {
			return nil, fmt.Errorf("postgres fallback certificate: %w", err)
		}
		certs = append(certs, *cert)
	}
	return certs, nil
}

func postgresManagedPostgresAuthority(cfg *config.Config) (capability.ManagedPostgresAuthority, []byte, error) {
	if cfg == nil || cfg.Options == nil || cfg.Options.InstallationID == "" {
		return capability.ManagedPostgresAuthority{}, nil, errors.New("postgres managed capability authority is incomplete")
	}
	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil || len(sharedKey) == 0 {
		return capability.ManagedPostgresAuthority{}, nil, errors.New("postgres managed capability shared key is unavailable")
	}
	authority, err := capability.NewManagedPostgresAuthority(cfg.Options.InstallationID, sharedKey)
	if err != nil {
		return capability.ManagedPostgresAuthority{}, nil, errors.New("postgres managed capability authority is incomplete")
	}
	return authority, append([]byte(nil), sharedKey...), nil
}

func materializePostgresRoute(
	options *config.Options,
	source *config.Policy,
	globalCA []byte,
) (*postgresRuntimeRoute, error) {
	if options == nil || source == nil || !source.IsPostgresUpstream() {
		return nil, errors.New("postgres route requires a postgres upstream")
	}
	routeURL, err := url.Parse(source.From)
	if err != nil || routeURL.Hostname() == "" {
		return nil, errors.New("postgres route hostname is invalid")
	}
	hostname, err := postgresidentity.ValidateRouteHostname(routeURL.Hostname())
	if err != nil {
		return nil, errors.New("postgres route hostname is invalid")
	}
	// Re-run route validation at the runtime materialization boundary. Config
	// sources normally validate earlier, but this prevents an unsupported
	// downstream client CA (or any other invalid route property) from becoming a
	// silent no-op if a caller constructs Config directly.
	policyRevision, err := source.PostgresRouteRevision()
	if err != nil {
		return nil, err
	}

	policy := *source
	routeCA, err := materializePostgresRouteCA(policy.TLSCustomCA, policy.TLSCustomCAFile)
	if err != nil {
		return nil, fmt.Errorf("postgres route %q custom CA: %w", hostname, err)
	}
	if len(routeCA) > 0 {
		policy.TLSCustomCA = base64.StdEncoding.EncodeToString(routeCA)
	}
	policy.TLSCustomCAFile = ""

	clientCert, clientCertPEM, clientKeyPEM, err := materializePostgresClientCertificate(&policy)
	if err != nil {
		return nil, fmt.Errorf("postgres route %q client certificate: %w", hostname, err)
	}
	policy.ClientCertificate = clientCert
	policy.TLSClientCertFile = ""
	policy.TLSClientKeyFile = ""

	idp, err := options.GetIdentityProviderForPolicy(&policy)
	if err != nil || idp.GetId() == "" {
		return nil, fmt.Errorf("postgres route %q identity provider is unavailable", hostname)
	}
	revision, err := postgresMaterialRouteRevision(
		policyRevision, idp.GetId(), globalCA, routeCA, clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, err
	}

	settings := policy.Postgres.Value
	if settings.AuthenticationMode.Value != configpb.PostgresAuthenticationMode_POSTGRES_AUTHENTICATION_MODE_MANAGED ||
		settings.Username.Value == "" || settings.Password.Value == "" || settings.Database.Value == "" {
		return nil, errors.New("postgres managed upstream credentials are incomplete")
	}
	upstream := policy.To[0].URL
	addr := upstream.Host
	if addr == "" {
		return nil, errors.New("postgres upstream host is required")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(upstream.Hostname(), "5432")
	}
	tlsConfig, err := postgresUpstreamTLSConfig(options, &policy, &upstream)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil && !tlsConfig.InsecureSkipVerify && tlsConfig.RootCAs == nil {
		tlsConfig.RootCAs, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("postgres system certificate pool: %w", err)
		}
	}

	return &postgresRuntimeRoute{
		hostname:                   hostname,
		revision:                   revision,
		policyRevision:             policyRevision,
		expectedIdentityProviderID: idp.GetId(),
		credentials: postgresproxy.UpstreamCredentials{
			Username: settings.Username.Value,
			Password: settings.Password.Value,
			Database: settings.Database.Value,
		},
		upstream: postgresproxy.UpstreamTarget{
			Addr:      addr,
			TLSConfig: tlsConfig,
		},
	}, nil
}

func materializePostgresCA(ca, caFile string) ([]byte, error) {
	if caFile != "" {
		return os.ReadFile(caFile)
	}
	if ca != "" {
		return base64.StdEncoding.DecodeString(ca)
	}
	return nil, nil
}

func materializePostgresRouteCA(ca, caFile string) ([]byte, error) {
	// Policy.Validate hydrates file contents into ca but retains caFile. Prefer
	// the file so a file-only generation receives fresh material.
	if caFile != "" {
		return os.ReadFile(caFile)
	}
	return materializePostgresCA(ca, "")
}

func materializePostgresClientCertificate(policy *config.Policy) (*tls.Certificate, []byte, []byte, error) {
	var certPEM, keyPEM []byte
	var err error
	if policy.TLSClientCertFile != "" || policy.TLSClientKeyFile != "" {
		if policy.TLSClientCertFile == "" || policy.TLSClientKeyFile == "" {
			return nil, nil, nil, errors.New("client certificate and key files must both be set")
		}
		certPEM, err = os.ReadFile(policy.TLSClientCertFile)
		if err != nil {
			return nil, nil, nil, err
		}
		keyPEM, err = os.ReadFile(policy.TLSClientKeyFile)
		if err != nil {
			return nil, nil, nil, err
		}
	} else if policy.TLSClientCert != "" || policy.TLSClientKey != "" {
		if policy.TLSClientCert == "" || policy.TLSClientKey == "" {
			return nil, nil, nil, errors.New("client certificate and key must both be set")
		}
		certPEM, err = base64.StdEncoding.DecodeString(policy.TLSClientCert)
		if err != nil {
			return nil, nil, nil, err
		}
		keyPEM, err = base64.StdEncoding.DecodeString(policy.TLSClientKey)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	if len(certPEM) == 0 && len(keyPEM) == 0 {
		return nil, nil, nil, nil
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	return &cert, certPEM, keyPEM, nil
}

func postgresMaterialRouteRevision(policyRevision, idpID string, materials ...[]byte) (string, error) {
	if policyRevision == "" || idpID == "" {
		return "", errors.New("postgres material route revision inputs are incomplete")
	}
	h := sha256.New()
	write := func(value []byte) {
		var size [8]byte
		binary.LittleEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(value)
	}
	write([]byte("pomerium-postgres-runtime-route-v1"))
	write([]byte(policyRevision))
	write([]byte(idpID))
	for _, material := range materials {
		digest := sha256.Sum256(material)
		write(digest[:])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type postgresCoreAdapter struct {
	runtime         *atomic.Pointer[postgresRuntimeSnapshot]
	authz           *authorize.Authorize
	managedPostgres capability.ManagedPostgresVerifier
}

const postgresSessionBindingClockSkew = time.Minute

func (a *postgresCoreAdapter) Authenticate(ctx context.Context, req postgresproxy.AuthRequest) (*postgresproxy.Session, error) {
	snapshot, err := a.currentRuntime()
	if err != nil {
		return nil, err
	}
	hostname, err := postgresidentity.ValidateRouteHostname(req.ServerName)
	if err != nil {
		return nil, errors.New("postgres route hostname is invalid")
	}
	route := snapshot.routes[hostname]
	if route == nil {
		return nil, fmt.Errorf("postgres route not found for SNI %q", req.ServerName)
	}
	identity, err := postgresidentity.ParseAndValidateCertificatePEM(
		[]byte(req.ClientCertPEM), route.hostname, time.Now())
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(req.ClientCertSHA256, hex.EncodeToString(identity.Fingerprint[:])) {
		return nil, errors.New("postgres client certificate fingerprint does not match TLS identity")
	}
	bindingID, binding, webSession, err := a.resolveSessionBinding(ctx, identity.BindingID)
	if err != nil {
		return nil, err
	}
	bindingHostname, err := postgresidentity.ValidateRouteHostname(binding.GetDetails()[postgresidentity.DetailRouteHostname])
	if err != nil || bindingHostname != route.hostname {
		return nil, errors.New("postgres session binding is for a different route")
	}
	if err := postgresSessionStillValid(webSession); err != nil {
		return nil, err
	}
	if err := validatePostgresSessionIdentityProvider(route.expectedIdentityProviderID, webSession); err != nil {
		return nil, err
	}
	if _, err := a.verifyManagedPostgres(ctx, snapshot); err != nil {
		return nil, err
	}
	var expiresAt time.Time
	if bindingExpiry := binding.GetExpiresAt(); bindingExpiry != nil {
		expiresAt = earliestPostgresExpiry(expiresAt, bindingExpiry.AsTime())
	}
	if sessionExpiry := webSession.GetExpiresAt(); sessionExpiry != nil && sessionExpiry.AsTime().Year() > 1970 {
		expiresAt = earliestPostgresExpiry(expiresAt, sessionExpiry.AsTime())
	}
	return &postgresproxy.Session{
		ID:                postgresConnectionID(req.ClientCertSHA256),
		PomeriumSessionID: binding.SessionId,
		SessionBindingID:  bindingID,
		UserID:            binding.UserId,
		RouteID:           route.revision,
		Hostname:          route.hostname,
		Database:          req.Database,
		DatabaseUser:      req.Username,
		ApplicationName:   req.ApplicationName,
		ClientAddr:        req.ClientAddr.String(),
		ClientCertSHA256:  req.ClientCertSHA256,
		ClientCertPEM:     req.ClientCertPEM,
		StartedAt:         time.Now(),
		ExpiresAt:         expiresAt,
	}, nil
}

func (a *postgresCoreAdapter) Reauthorize(ctx context.Context, session *postgresproxy.Session) error {
	snapshot, err := a.currentRuntime()
	if err != nil {
		return err
	}
	if _, err := a.verifyManagedPostgres(ctx, snapshot); err != nil {
		return err
	}
	_, binding, webSession, err := a.resolveSessionBinding(ctx, session.SessionBindingID)
	if err != nil {
		return err
	}
	if binding.SessionId != session.PomeriumSessionID || binding.UserId != session.UserID {
		return errors.New("postgres session binding no longer matches the connection")
	}
	bindingHostname, err := postgresidentity.ValidateRouteHostname(binding.GetDetails()[postgresidentity.DetailRouteHostname])
	if err != nil || bindingHostname != session.Hostname {
		return errors.New("postgres session binding no longer matches the route")
	}
	if err := postgresSessionStillValid(webSession); err != nil {
		return err
	}
	route, err := a.routeForSession(snapshot, session)
	if err != nil {
		return err
	}
	if err := validatePostgresSessionIdentityProvider(route.expectedIdentityProviderID, webSession); err != nil {
		return err
	}
	return a.authorizeSession(ctx, snapshot, route, session)
}

func (a *postgresCoreAdapter) UpstreamCredentials(ctx context.Context, session *postgresproxy.Session) (*postgresproxy.UpstreamCredentials, error) {
	snapshot, err := a.currentRuntime()
	if err != nil {
		return nil, err
	}
	if _, err := a.verifyManagedPostgres(ctx, snapshot); err != nil {
		return nil, err
	}
	route, err := a.routeForSession(snapshot, session)
	if err != nil {
		return nil, err
	}
	credentials := route.credentials
	return &credentials, nil
}

func (a *postgresCoreAdapter) AuthorizeSession(ctx context.Context, session *postgresproxy.Session) error {
	snapshot, err := a.currentRuntime()
	if err != nil {
		return err
	}
	route, err := a.routeForSession(snapshot, session)
	if err != nil {
		return err
	}
	return a.authorizeSession(ctx, snapshot, route, session)
}

func (a *postgresCoreAdapter) authorizeSession(
	ctx context.Context,
	snapshot *postgresRuntimeSnapshot,
	route *postgresRuntimeRoute,
	session *postgresproxy.Session,
) error {
	res, err := a.authz.EvaluatePostgresSession(ctx, postgresRequestFromSession(
		session, snapshot.configGeneration, route.policyRevision))
	if err != nil {
		return err
	}
	if !postgresEvaluationAllowed(res) {
		return fmt.Errorf("postgres session denied by policy: %s", postgresEvaluationReason(res))
	}
	return nil
}

func (a *postgresCoreAdapter) ResolveUpstream(_ context.Context, session *postgresproxy.Session) (*postgresproxy.UpstreamTarget, error) {
	snapshot, err := a.currentRuntime()
	if err != nil {
		return nil, err
	}
	route, err := a.routeForSession(snapshot, session)
	if err != nil {
		return nil, err
	}
	target := route.upstream
	if target.TLSConfig != nil {
		target.TLSConfig = target.TLSConfig.Clone()
	}
	return &target, nil
}

func (a *postgresCoreAdapter) routeForSession(snapshot *postgresRuntimeSnapshot, session *postgresproxy.Session) (*postgresRuntimeRoute, error) {
	if session == nil {
		return nil, errors.New("postgres session is required")
	}
	if snapshot == nil || snapshot.configGeneration == nil || snapshot.routes == nil {
		return nil, errors.New("postgres runtime configuration is not ready")
	}
	hostname, err := postgresidentity.ValidateRouteHostname(session.Hostname)
	if err != nil {
		return nil, errors.New("postgres session route hostname is invalid")
	}
	route := snapshot.routes[hostname]
	if route == nil {
		return nil, fmt.Errorf("postgres route not found for SNI %q", session.Hostname)
	}
	if session.RouteID == "" || route.revision != session.RouteID {
		return nil, errors.New("postgres route changed during session")
	}
	return route, nil
}

func (a *postgresCoreAdapter) currentRuntime() (*postgresRuntimeSnapshot, error) {
	if a != nil && a.runtime != nil {
		if snapshot := a.runtime.Load(); snapshot != nil && snapshot.configGeneration != nil && snapshot.routes != nil {
			return snapshot, nil
		}
	}
	return nil, errors.New("postgres runtime configuration is not ready")
}

func postgresRequestFromSession(
	session *postgresproxy.Session,
	configGeneration *config.Config,
	policyRevision string,
) authorize.PostgresRequest {
	if session == nil {
		return authorize.PostgresRequest{}
	}
	return authorize.PostgresRequest{
		Hostname:         session.Hostname,
		SessionID:        session.PomeriumSessionID,
		SessionBindingID: session.SessionBindingID,
		SourceAddress:    postgresSourceAddress(session.ClientAddr),
		ClientCertPEM:    session.ClientCertPEM,
		ProtocolSession:  session,
		RouteRevision:    policyRevision,
		ConfigGeneration: configGeneration,
	}
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
	if resp.GetRecord() == nil {
		return "", nil, nil, errors.New("postgres session binding not found")
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
	if binding.GetSessionId() == "" || binding.GetUserId() == "" {
		return "", nil, nil, errors.New("postgres session binding identity is incomplete")
	}
	if strings.TrimSpace(binding.GetDetails()[postgresidentity.DetailRouteHostname]) == "" {
		return "", nil, nil, errors.New("postgres session binding route is required")
	}
	now := time.Now()
	issuedAt := binding.GetIssuedAt()
	if issuedAt == nil || issuedAt.AsTime().Year() <= 1970 {
		return "", nil, nil, errors.New("postgres session binding issued_at is required")
	}
	if err := issuedAt.CheckValid(); err != nil {
		return "", nil, nil, errors.New("postgres session binding issued_at is invalid")
	}
	if issuedAt.AsTime().After(now.Add(postgresSessionBindingClockSkew)) {
		return "", nil, nil, errors.New("postgres session binding issued_at is in the future")
	}
	expiresAt := binding.GetExpiresAt()
	if expiresAt == nil || expiresAt.AsTime().Year() <= 1970 {
		return "", nil, nil, errors.New("postgres session binding expiry is required")
	}
	if err := expiresAt.CheckValid(); err != nil {
		return "", nil, nil, errors.New("postgres session binding expiry is invalid")
	}
	if expiresAt.AsTime().Before(issuedAt.AsTime()) {
		return "", nil, nil, errors.New("postgres session binding expiry precedes issued_at")
	}
	if !expiresAt.AsTime().After(now) {
		return "", nil, nil, errors.New("postgres session binding expired")
	}

	sessionResp, err := client.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(sessionpb.Session)),
		Id:   binding.SessionId,
	})
	if err != nil {
		return "", nil, nil, err
	}
	if sessionResp.GetRecord() == nil {
		return "", nil, nil, errors.New("postgres web session not found")
	}
	if sessionResp.GetRecord().GetDeletedAt() != nil {
		return "", nil, nil, errors.New("postgres web session deleted")
	}
	var webSession sessionpb.Session
	if err := sessionResp.GetRecord().GetData().UnmarshalTo(&webSession); err != nil {
		return "", nil, nil, err
	}
	if webSession.GetId() == "" || webSession.GetUserId() == "" || webSession.GetIdpId() == "" {
		return "", nil, nil, errors.New("postgres web session identity is incomplete")
	}
	if webSession.GetId() != binding.GetSessionId() || webSession.GetUserId() != binding.GetUserId() {
		return "", nil, nil, errors.New("postgres session binding no longer matches the web session")
	}
	if err := postgresSessionStillValid(&webSession); err != nil {
		return "", nil, nil, err
	}
	return bindingID, &binding, &webSession, nil
}

func postgresSessionStillValid(s *sessionpb.Session) error {
	if s == nil {
		return errors.New("postgres web session missing")
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("postgres web session invalid: %w", err)
	}
	return nil
}

func validatePostgresSessionIdentityProvider(expectedID string, webSession *sessionpb.Session) error {
	if expectedID == "" || webSession == nil {
		return errors.New("postgres session identity provider cannot be verified")
	}
	if webSession.GetIdpId() != expectedID {
		return errors.New("postgres web session identity provider no longer matches the route")
	}
	return nil
}

func (a *postgresCoreAdapter) verifyManagedPostgres(ctx context.Context, snapshot *postgresRuntimeSnapshot) (time.Time, error) {
	if a == nil || a.managedPostgres == nil || snapshot == nil {
		return time.Time{}, capability.ErrDenied
	}
	expiresAt, err := a.managedPostgres.VerifyManagedPostgres(ctx, snapshot.managedPostgresAuthority)
	if err != nil || !expiresAt.After(time.Now()) {
		return time.Time{}, capability.ErrDenied
	}
	return expiresAt, nil
}

func earliestPostgresExpiry(expiries ...time.Time) time.Time {
	var earliest time.Time
	for _, expiry := range expiries {
		if expiry.IsZero() {
			continue
		}
		if earliest.IsZero() || expiry.Before(earliest) {
			earliest = expiry
		}
	}
	return earliest
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
	if policy == nil || !policy.Postgres.IsSet {
		return nil, errors.New("postgres managed upstream settings are required")
	}
	switch tlsMode := policy.Postgres.Value.UpstreamTlsMode.Value; tlsMode {
	case configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_DISABLE:
		return nil, nil
	case configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_UNSPECIFIED,
		configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_VERIFY_FULL:
	case configpb.PostgresUpstreamTLSMode_POSTGRES_UPSTREAM_TLS_MODE_REQUIRE:
		// Match libpq sslmode=require: encrypt the upstream hop without
		// verifying the server certificate. The default mode is stricter and
		// verifies the server name.
		tlsConfig.InsecureSkipVerify = true
	default:
		return nil, fmt.Errorf("postgres upstream TLS mode %d is not supported", tlsMode)
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
