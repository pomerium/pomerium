package testenv

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/grpclog"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/config/otelconfig"
	databroker_service "github.com/pomerium/pomerium/databroker"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/testenv/envutil"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/derivecert"
	"github.com/pomerium/pomerium/pkg/envoy"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/netutil"
	"github.com/pomerium/pomerium/pkg/slices"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// Environment is a lightweight integration test fixture that runs Pomerium
// in-process.
type Environment interface {
	// Context returns the environment's root context. This context holds a
	// top-level logger scoped to this environment. It will be canceled when
	// Stop() is called, or during test cleanup.
	Context() context.Context
	Tracer() oteltrace.Tracer

	Assert() *assert.Assertions
	Require() *require.Assertions

	// TempDir returns a unique temp directory for this context. Calling this
	// function multiple times returns the same path.
	TempDir() string
	// CACert returns the test environment's root CA certificate and private key.
	CACert() *tls.Certificate
	// ServerCAs returns a new [*x509.CertPool] containing the root CA certificate
	// used to sign the server cert and other test certificates.
	ServerCAs() *x509.CertPool
	// ServerCert returns the Pomerium server's certificate and private key.
	ServerCert() *tls.Certificate
	// NewClientCert generates a new client certificate signed by the root CA
	// certificate. One or more optional templates can be given, which can be
	// used to set or override certain parameters when creating a certificate,
	// including subject, SANs, or extensions. If more than one template is
	// provided, they will be applied in order from left to right.
	//
	// By default (unless overridden in a template), the certificate will have
	// its Common Name set to the file:line string of the call site. Calls to
	// NewClientCert() on different lines will have different subjects. If
	// multiple certs with the same subject are needed, wrap the call to this
	// function in another helper function, or separate calls with commas on the
	// same line.
	NewClientCert(templateOverrides ...*x509.Certificate) *Certificate

	NewServerCert(templateOverrides ...*x509.Certificate) *Certificate

	AuthenticateURL() values.Value[string]
	DatabrokerURL() values.Value[string]
	Ports() Ports
	SharedSecret() []byte
	CookieSecret() []byte

	NewDataBrokerServiceClient() databroker.DataBrokerServiceClient

	Config() *config.Config

	// Add adds the given [Modifier] to the environment. All modifiers will be
	// invoked upon calling Start() to apply individual modifications to the
	// configuration before starting the Pomerium server.
	Add(m Modifier)
	// AddTask adds the given [Task] to the environment. All tasks will be
	// started in separate goroutines upon calling Start(). If any tasks exit
	// with an error, the environment will be stopped and the test will fail.
	AddTask(r Task)
	// AddUpstream adds the given [Upstream] to the environment. This function is
	// equivalent to calling both Add() and AddTask() with the upstream, but
	// improves readability.
	AddUpstream(u Upstream)

	// Start starts the test environment, and adds a call to Stop() as a cleanup
	// hook to the environment's [testing.T]. All previously added [Modifier]
	// instances are invoked in order to build the configuration, and all
	// previously added [Task] instances are started in the background.
	//
	// Calling Start() more than once, Calling Start() after Stop(), or calling
	// any of the Add* functions after Start() will panic.
	Start()
	// Stop stops the test environment. Calling this function more than once has
	// no effect. It is usually not necessary to call Stop() directly unless you
	// need to stop the test environment before the test is completed.
	Stop()
	// Pause will block and wait until SIGINT is received, then continue. This
	// has the same effect as if the test failed and the PauseOnFailure option was
	// given, but can be called at any time.
	Pause()

	// SubdomainURL returns a string [values.Value] which will contain a complete
	// URL for the given subdomain of the server's domain (given by its serving
	// certificate), including the 'https://' scheme and random http server port.
	// This value will only be resolved some time after Start() is called, and
	// can be used as the 'from' value for routes.
	SubdomainURL(subdomain string) values.Value[string]

	// NewLogRecorder returns a new [*LogRecorder] and starts capturing logs for
	// the Pomerium server and Envoy.
	NewLogRecorder(opts ...LogRecorderOption) *LogRecorder

	// GetState returns the current state of the test environment.
	GetState() EnvironmentState

	// OnStateChanged registers a callback to be invoked when the environment's
	// state changes to the given state. Each callback is invoked in a separate
	// goroutine, but the test environment will wait for all callbacks to return
	// before continuing, after triggering the state change.
	//
	// Calling the returned stop function will prevent the callback from being
	// run. Returns true if it stopped the callback from being run, or false if
	// it already ran or is currently running.
	//
	// If the environment is already in the given state, the callback will be run
	// in a separate goroutine immediately and the returned stop function will
	// have no effect. A callback run in this way will prevent the state from
	// advancing until the callback returns.
	//
	// State changes are triggered in the following places:
	// - NotRunning->Starting: in Start(), as the first operation
	// - Starting->Running: in Start(), just before returning
	// - Running->Stopping: in Stop(), just before the env context is canceled
	// - Stopping->Stopped: in Stop(), after all tasks have completed
	OnStateChanged(state EnvironmentState, callback func()) (stop func() bool)
}

type Certificate tls.Certificate

func (c *Certificate) Fingerprint() string {
	sum := sha256.Sum256(c.Leaf.Raw)
	return hex.EncodeToString(sum[:])
}

func (c *Certificate) SPKIHash() string {
	sum := sha256.Sum256(c.Leaf.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

type EnvironmentState uint32

const (
	NotRunning EnvironmentState = iota
	Starting
	Running
	Stopping
	Stopped
)

func (e EnvironmentState) String() string {
	switch e {
	case NotRunning:
		return "NotRunning"
	case Starting:
		return "Starting"
	case Running:
		return "Running"
	case Stopping:
		return "Stopping"
	case Stopped:
		return "Stopped"
	default:
		return fmt.Sprintf("EnvironmentState(%d)", e)
	}
}

type environment struct {
	EnvironmentOptions
	t               testing.TB
	assert          *assert.Assertions
	require         *require.Assertions
	tempDir         string
	domain          string
	ports           Ports
	sharedSecret    [32]byte
	cookieSecret    [32]byte
	workspaceFolder string
	silent          bool
	caPEM           []byte
	caKeyPEM        []byte
	trustedPEM      []byte
	trustedKeyPEM   []byte

	ctx            context.Context
	cancel         context.CancelCauseFunc
	cleanupOnce    sync.Once
	logWriter      *log.MultiWriter
	tracerProvider oteltrace.TracerProvider
	tracer         oteltrace.Tracer
	rootSpan       oteltrace.Span

	mods         []WithCaller[Modifier]
	tasks        []WithCaller[Task]
	taskErrGroup *errgroup.Group

	stateMu              sync.Mutex
	state                EnvironmentState
	stateChangeListeners map[EnvironmentState][]func()
	stateChangeBlockers  sync.WaitGroup

	src *configSource

	provider *health.ChannelProvider
}

type EnvironmentOptions struct {
	debug           bool
	pauseOnFailure  bool
	forceSilent     bool
	traceDebugFlags trace.DebugFlags
	traceClient     otlptrace.Client
	traceConfig     *otelconfig.Config
	host            string
}

type EnvironmentOption func(*EnvironmentOptions)

func (o *EnvironmentOptions) apply(opts ...EnvironmentOption) {
	for _, op := range opts {
		op(o)
	}
}

func Debug(enable ...bool) EnvironmentOption {
	if len(enable) == 0 {
		enable = append(enable, true)
	}
	return func(o *EnvironmentOptions) {
		o.debug = enable[0]
	}
}

func PauseOnFailure(enable ...bool) EnvironmentOption {
	if len(enable) == 0 {
		enable = append(enable, true)
	}
	return func(o *EnvironmentOptions) {
		o.pauseOnFailure = enable[0]
	}
}

func Silent(silent ...bool) EnvironmentOption {
	if len(silent) == 0 {
		silent = append(silent, true)
	}
	return func(o *EnvironmentOptions) {
		o.forceSilent = silent[0]
	}
}

const StandardTraceDebugFlags = trace.TrackSpanCallers |
	trace.WarnOnIncompleteSpans |
	trace.WarnOnIncompleteTraces |
	trace.WarnOnUnresolvedReferences |
	trace.LogTraceIDsOnWarn |
	trace.LogAllSpansOnWarn

func WithTraceDebugFlags(flags trace.DebugFlags) EnvironmentOption {
	return func(o *EnvironmentOptions) {
		o.traceDebugFlags = flags
	}
}

func WithTraceClient(traceClient otlptrace.Client) EnvironmentOption {
	return func(o *EnvironmentOptions) {
		o.traceClient = traceClient
	}
}

func WithTraceConfig(traceConfig *otelconfig.Config) EnvironmentOption {
	return func(o *EnvironmentOptions) {
		o.traceConfig = traceConfig
	}
}

func init() {
	grpclog.SetLoggerV2(grpclog.NewLoggerV2WithVerbosity(io.Discard, io.Discard, io.Discard, 0))
}

const defaultTraceDebugFlags = trace.TrackSpanCallers | trace.TrackSpanReferences

var (
	flagDebug              = flag.Bool("env.debug", false, "enables test environment debug logging (equivalent to Debug() option)")
	flagPauseOnFailure     = flag.Bool("env.pause-on-failure", false, "enables pausing the test environment on failure (equivalent to PauseOnFailure() option)")
	flagSilent             = flag.Bool("env.silent", false, "suppresses all test environment output (equivalent to Silent() option)")
	flagTraceDebugFlags    = flag.String("env.trace-debug-flags", strconv.Itoa(defaultTraceDebugFlags), "trace debug flags (equivalent to TraceDebugFlags() option)")
	flagBindAddress        = flag.String("env.bind-address", "", "bind address for local services")
	flagTraceEnvironConfig = flag.Bool("env.use-trace-environ", false, "if true, will configure a trace client from environment variables if no trace client has been set")
)

func New(t testing.TB, opts ...EnvironmentOption) Environment {
	mgr := health.GetProviderManager()
	addTraceDebugFlags := strings.HasPrefix(*flagTraceDebugFlags, "+")
	defaultTraceDebugFlags, err := strconv.Atoi(strings.TrimPrefix(*flagTraceDebugFlags, "+"))
	if err != nil {
		panic("malformed value for --env.trace-debug-flags: " + err.Error())
	}
	options := EnvironmentOptions{
		debug:           *flagDebug,
		pauseOnFailure:  *flagPauseOnFailure,
		forceSilent:     *flagSilent,
		traceDebugFlags: trace.DebugFlags(defaultTraceDebugFlags),
		traceClient:     trace.NoopClient{},
		host:            *flagBindAddress,
	}
	options.apply(opts...)
	if testing.Short() {
		t.Helper()
		t.Skip("test environment disabled in short mode")
	}
	if addTraceDebugFlags {
		options.traceDebugFlags |= trace.DebugFlags(defaultTraceDebugFlags)
	}
	if *flagTraceEnvironConfig && options.traceConfig == nil &&
		(reflect.TypeOf(options.traceClient) == reflect.TypeFor[trace.NoopClient]()) {
		cfg := newOtelConfigFromEnv(t)
		options.traceConfig = &cfg
		client, err := trace.NewTraceClientFromConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("tracing configured from environment")
		options.traceClient = client
	}
	trace.UseGlobalPanicTracer()
	databroker.DebugUseFasterBackoff.Store(true)
	workspaceFolder, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(workspaceFolder, "go.mod")); err == nil {
			break
		}
		workspaceFolder = filepath.Dir(workspaceFolder)
		if workspaceFolder == "/" {
			panic("could not find workspace root")
		}
	}
	workspaceFolder, err = filepath.Abs(workspaceFolder)
	require.NoError(t, err)

	writer := log.NewMultiWriter()
	silent := options.forceSilent || isSilent(t)
	if silent {
		// this sets the global zap level to fatal, then resets the global zerolog
		// level to debug
		log.SetLevel(zerolog.FatalLevel)
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		log.SetLevel(zerolog.InfoLevel)
		writer.Add(os.Stdout)
	}
	log.DebugDisableGlobalWarnings.Store(silent)
	log.DebugDisableGlobalMessages.Store(silent)
	log.DebugDisableZapLogger.Store(silent)

	logger := zerolog.New(writer).With().Timestamp().Logger().Level(zerolog.DebugLevel)

	ctx := trace.Options{
		DebugFlags: options.traceDebugFlags,
	}.NewContext(logger.WithContext(context.Background()), options.traceClient) //nolint:usetesting
	tracerProvider := trace.NewTracerProvider(ctx, "Test Environment")
	tracer := tracerProvider.Tracer(trace.PomeriumCoreTracer)
	ctx, span := tracer.Start(ctx, t.Name(), oteltrace.WithNewRoot())
	require.NoError(t, err)

	ctx, cancel := context.WithCancelCause(ctx)
	taskErrGroup, ctx := errgroup.WithContext(ctx)

	// TODO : add correct checks when they're implemented
	chP := health.NewChannelProvider(
		mgr,
		health.WithExpectedChecks(
		// health.BuildDatabrokerConfig,
		// health.StorageBackend,
		// health.XDSCluster,
		// health.XDSListener,
		// health.XDSRouteConfiguration,
		),
	)

	mgr.Register(health.ProviderID("testenv-reporter"), chP)

	e := &environment{
		EnvironmentOptions: options,
		t:                  t,
		assert:             assert.New(t),
		require:            require.New(t),
		tempDir:            tempDir(t),
		ports: Ports{
			ProxyHTTP:    values.Deferred[netip.AddrPort](),
			ProxyGRPC:    values.Deferred[netip.AddrPort](),
			ProxySSH:     values.Deferred[netip.AddrPort](),
			ProxyMetrics: values.Deferred[netip.AddrPort](),
			EnvoyAdmin:   values.Deferred[netip.AddrPort](),
			GRPC:         values.Deferred[netip.AddrPort](),
			HTTP:         values.Deferred[netip.AddrPort](),
			Outbound:     values.Deferred[netip.AddrPort](),
			Metrics:      values.Deferred[netip.AddrPort](),
			Debug:        values.Deferred[netip.AddrPort](),
			ALPN:         values.Deferred[netip.AddrPort](),
			Health:       values.Deferred[netip.AddrPort](),
		},
		workspaceFolder:      workspaceFolder,
		silent:               silent,
		ctx:                  ctx,
		cancel:               cancel,
		tracerProvider:       tracerProvider,
		tracer:               tracer,
		logWriter:            writer,
		taskErrGroup:         taskErrGroup,
		stateChangeListeners: make(map[EnvironmentState][]func()),
		rootSpan:             span,
		provider:             chP,
	}

	mgr.Register(health.ProviderID("testenv"), e)

	_, err = rand.Read(e.sharedSecret[:])
	require.NoError(t, err)
	_, err = rand.Read(e.cookieSecret[:])
	require.NoError(t, err)

	ca, err := derivecert.NewCA(nil)
	require.NoError(t, err)
	caPEM, err := ca.PEM()
	require.NoError(t, err)
	e.caPEM = caPEM.Cert
	e.caKeyPEM = caPEM.Key
	certPEM, err := ca.NewServerCert([]string{"*.sslip.io"})
	require.NoError(t, err)
	e.trustedPEM = certPEM.Cert
	e.trustedKeyPEM = certPEM.Key

	e.domain = wildcardDomain(e.ServerCert().Leaf.DNSNames)

	return e
}

func (e *environment) debugf(format string, args ...any) {
	e.t.Helper()
	if e.rootSpan.IsRecording() {
		e.rootSpan.AddEvent(fmt.Sprintf(format, args...))
	}
	if !e.debug {
		return
	}
	e.t.Logf("\x1b[34mDEBUG ["+e.t.Name()+"] "+format+"\x1b[0m", args...)
}

type WithCaller[T any] struct {
	Caller string
	Value  T
}

type Ports struct {
	ProxyHTTP    values.MutableValue[netip.AddrPort]
	ProxyGRPC    values.MutableValue[netip.AddrPort]
	ProxySSH     values.MutableValue[netip.AddrPort]
	ProxyMetrics values.MutableValue[netip.AddrPort]
	EnvoyAdmin   values.MutableValue[netip.AddrPort]
	GRPC         values.MutableValue[netip.AddrPort]
	HTTP         values.MutableValue[netip.AddrPort]
	Outbound     values.MutableValue[netip.AddrPort]
	Metrics      values.MutableValue[netip.AddrPort]
	Debug        values.MutableValue[netip.AddrPort]
	ALPN         values.MutableValue[netip.AddrPort]
	Health       values.MutableValue[netip.AddrPort]
}

func (e *environment) TempDir() string {
	return e.tempDir
}

func (e *environment) Context() context.Context {
	return ContextWithEnv(e.ctx, e)
}

func (e *environment) Tracer() oteltrace.Tracer {
	return e.tracer
}

func (e *environment) Assert() *assert.Assertions {
	return e.assert
}

func (e *environment) Require() *require.Assertions {
	return e.require
}

func (e *environment) SubdomainURL(subdomain string) values.Value[string] {
	return values.Bind(e.ports.ProxyHTTP, func(addr netip.AddrPort) string {
		return fmt.Sprintf("https://%s:%d", GetSubDomainForAddress(subdomain, addr.Addr()), addr.Port())
	})
}

func (e *environment) AuthenticateURL() values.Value[string] {
	return e.SubdomainURL("authenticate")
}

func (e *environment) DatabrokerURL() values.Value[string] {
	return values.Bind(e.ports.Outbound, func(addr netip.AddrPort) string {
		return addr.String()
	})
}

func (e *environment) Ports() Ports {
	return e.ports
}

func (e *environment) Config() *config.Config {
	return e.src.GetConfig()
}

func (e *environment) CACert() *tls.Certificate {
	caCert, err := tls.X509KeyPair(e.caPEM, e.caKeyPEM)
	require.NoError(e.t, err)
	return &caCert
}

func (e *environment) ServerCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.caPEM)
	return pool
}

func (e *environment) ServerCert() *tls.Certificate {
	serverCert, err := tls.X509KeyPair(e.trustedPEM, e.trustedKeyPEM)
	require.NoError(e.t, err)
	return &serverCert
}

// Used as the context's cancel cause during normal cleanup
var ErrCauseTestCleanup = errors.New("test cleanup")

// Used as the context's cancel cause when Stop() is called
var ErrCauseManualStop = errors.New("Stop() called")

func (e *environment) Start() {
	_, span := e.tracer.Start(e.Context(), "Start")
	defer span.End()
	e.debugf("Start()")
	e.advanceState(Starting)
	e.t.Cleanup(e.onTestCleanup)
	e.t.Setenv("TMPDIR", e.TempDir())
	e.debugf("temp dir: %s", e.TempDir())

	cfg := &config.Config{
		Options: config.NewDefaultOptions(),
	}

	var addrs []netip.AddrPort
	if e.host != "" {
		addr, err := netip.ParseAddr(e.host)
		require.NoError(e.t, err)
		addrs, err = netutil.AllocatePorts(addr, 12)
		require.NoError(e.t, err)
	} else {
		var err error
		addrs, err = netutil.AllocateAddresses(12)
		require.NoError(e.t, err)
	}

	e.ports.ProxyHTTP.Resolve(addrs[0])
	e.ports.ProxyGRPC.Resolve(addrs[1])
	e.ports.ProxySSH.Resolve(addrs[2])
	e.ports.ProxyMetrics.Resolve(addrs[3])
	e.ports.EnvoyAdmin.Resolve(addrs[4])
	e.ports.Health.Resolve(addrs[5])
	e.ports.GRPC.Resolve(addrs[6])
	e.ports.HTTP.Resolve(addrs[7])
	e.ports.Outbound.Resolve(addrs[8])
	e.ports.Metrics.Resolve(addrs[9])
	e.ports.Debug.Resolve(addrs[10])
	e.ports.ALPN.Resolve(addrs[11])
	cfg.AllocateAddresses(*(*[6]netip.AddrPort)(addrs[6:]))

	cfg.Options.AutocertOptions = config.AutocertOptions{Enable: false}
	cfg.Options.Services = "all"
	cfg.Options.LogLevel = config.LogLevelDebug
	cfg.Options.ProxyLogLevel = config.LogLevelInfo
	cfg.Options.Addr = e.ports.ProxyHTTP.Value().String()
	cfg.Options.GRPCAddr = e.ports.ProxyGRPC.Value().String()
	cfg.Options.SSHAddr = e.ports.ProxySSH.Value().String()
	cfg.Options.EnvoyAdminAddress = e.ports.EnvoyAdmin.Value().String()
	cfg.Options.MetricsAddr = e.ports.ProxyMetrics.Value().String()
	cfg.Options.CA = base64.StdEncoding.EncodeToString(e.caPEM)
	cfg.Options.Cert = base64.StdEncoding.EncodeToString(e.trustedPEM)
	cfg.Options.Key = base64.StdEncoding.EncodeToString(e.trustedKeyPEM)
	cfg.Options.AuthenticateURLString = e.AuthenticateURL().Value()
	cfg.Options.DataBroker.StorageType = "memory"
	cfg.Options.SharedKey = base64.StdEncoding.EncodeToString(e.sharedSecret[:])
	cfg.Options.CookieSecret = base64.StdEncoding.EncodeToString(e.cookieSecret[:])
	cfg.Options.AccessLogFields = []log.AccessLogField{
		log.AccessLogFieldAuthority,
		log.AccessLogFieldDuration,
		log.AccessLogFieldForwardedFor,
		log.AccessLogFieldIP,
		log.AccessLogFieldMethod,
		log.AccessLogFieldPath,
		log.AccessLogFieldQuery,
		log.AccessLogFieldReferer,
		log.AccessLogFieldRequestID,
		log.AccessLogFieldResponseCode,
		log.AccessLogFieldResponseCodeDetails,
		log.AccessLogFieldSize,
		log.AccessLogFieldUpstreamCluster,
		log.AccessLogFieldUserAgent,
		log.AccessLogFieldClientCertificate,
	}
	cfg.Options.HealthCheckAddr = e.ports.Health.Value().String()
	if e.traceConfig != nil {
		cfg.Options.Tracing = *e.traceConfig
	}

	e.src = &configSource{cfg: cfg}
	e.AddTask(TaskFunc(func(ctx context.Context) error {
		fileMgr := filemgr.NewManager(filemgr.WithCacheDir(filepath.Join(e.TempDir(), "cache")))
		for _, mod := range e.mods {
			mod.Value.Modify(cfg)
			require.NoError(e.t, cfg.Options.Validate(), "invoking modifier resulted in an invalid configuration:\nadded by: "+mod.Caller)
		}

		opts := []pomerium.Option{
			pomerium.WithOverrideFileManager(fileMgr),
			pomerium.WithEnvoyServerOptions(envoy.WithExitGracePeriod(30 * time.Second)),
			pomerium.WithDataBrokerServerOptions(
				databroker_service.WithManagerOptions(manager.WithLeaseTTL(1 * time.Second)),
			),
		}
		envoyBinaryPath := filepath.Join(e.workspaceFolder, fmt.Sprintf("pkg/envoy/files/envoy-%s-%s", runtime.GOOS, runtime.GOARCH))
		if envutil.EnvoyProfilerAvailable(envoyBinaryPath) {
			e.debugf("envoy profiling available")
			envVars := []string{}
			pprofCmdLog := "=> go run github.com/google/pprof@latest -symbolize=local -ignore='TCMalloc|^tcmalloc::|^msync$|stacktrace_generic_fp' -http=: %s %s"
			if path := envutil.ProfileOutputPath("cpuprofile"); path != "" {
				dir, base := filepath.Split(path)
				path = filepath.Join(dir, "envoy_"+base)
				envVars = append(envVars, fmt.Sprintf("CPUPROFILE=%s", path))
				e.t.Cleanup(func() {
					e.debugf("View envoy cpu profile:")
					e.debugf(pprofCmdLog, envoyBinaryPath, path)
				})
			}
			if path := envutil.ProfileOutputPath("memprofile"); path != "" {
				dir, base := filepath.Split(path)
				path = filepath.Join(dir, "envoy_"+base)
				envVars = append(envVars, fmt.Sprintf("HEAPPROFILE=%s", path))
				e.t.Cleanup(func() {
					if err := envutil.CollectEnvoyHeapProfiles(path); err != nil {
						e.t.Logf("error collecting envoy heap profiles: %s", err)
					}
					e.debugf("View envoy heap profile:")
					envoyBinaryPath := filepath.Join(e.workspaceFolder, fmt.Sprintf("pkg/envoy/files/envoy-%s-%s", runtime.GOOS, runtime.GOARCH))
					e.debugf(pprofCmdLog, envoyBinaryPath, path)
				})
			}
			if len(envVars) > 0 {
				e.debugf("adding envoy env vars: %v\n", envVars)
				opts = append(opts, pomerium.WithEnvoyServerOptions(envoy.WithExtraEnvVars(envVars...)))
			}
		} else {
			e.debugf("envoy profiling not available")
		}

		pom := pomerium.New(opts...)
		startDone := make(chan error, 1)
		e.OnStateChanged(Stopping, func() {
			startErr := <-startDone
			if startErr != nil {
				return // Start() failed, so there is nothing to shut down
			}
			if err := pom.Shutdown(ctx); err != nil {
				log.Ctx(ctx).Err(err).Msg("error shutting down pomerium server")
			} else {
				e.debugf("pomerium server shut down without error")
			}
		})
		err := pom.Start(ctx, e.tracerProvider, e.src)
		startDone <- err
		require.NoError(e.t, err)
		return pom.Wait()
	}))

	for i, task := range e.tasks {
		log.Ctx(e.Context()).Debug().Str("caller", task.Caller).Msgf("starting task %d", i)
		e.taskErrGroup.Go(func() error {
			defer log.Ctx(e.Context()).Debug().Str("caller", task.Caller).Msgf("task %d exited", i)
			return task.Value.Run(e.Context())
		})
	}

	runtime.Gosched()

	e.advanceState(Running)
}

func (e *environment) NewClientCert(templateOverrides ...*x509.Certificate) *Certificate {
	caCert := e.CACert()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(e.t, err)

	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(e.t, err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName: getCaller(),
		},
		NotBefore: now,
		NotAfter:  now.Add(12 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	for _, override := range templateOverrides {
		tmpl.CRLDistributionPoints = slices.Unique(append(tmpl.CRLDistributionPoints, override.CRLDistributionPoints...))
		tmpl.DNSNames = slices.Unique(append(tmpl.DNSNames, override.DNSNames...))
		tmpl.EmailAddresses = slices.Unique(append(tmpl.EmailAddresses, override.EmailAddresses...))
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, override.ExtraExtensions...)
		tmpl.IPAddresses = slices.UniqueBy(append(tmpl.IPAddresses, override.IPAddresses...), net.IP.String)
		tmpl.URIs = slices.UniqueBy(append(tmpl.URIs, override.URIs...), (*url.URL).String)
		tmpl.UnknownExtKeyUsage = slices.UniqueBy(append(tmpl.UnknownExtKeyUsage, override.UnknownExtKeyUsage...), asn1.ObjectIdentifier.String)
		seq := override.Subject.ToRDNSequence()
		tmpl.Subject.FillFromRDNSequence(&seq)
		tmpl.KeyUsage |= override.KeyUsage
		tmpl.ExtKeyUsage = slices.Unique(append(tmpl.ExtKeyUsage, override.ExtKeyUsage...))
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert.Leaf, priv.Public(), caCert.PrivateKey)
	require.NoError(e.t, err)

	cert, err := x509.ParseCertificate(clientCertDER)
	require.NoError(e.t, err)
	e.debugf("provisioned client certificate for %s", cert.Subject.String())

	clientCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw, caCert.Leaf.Raw},
		PrivateKey:  priv,
		Leaf:        cert,
	}

	_, err = clientCert.Leaf.Verify(x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		Roots: e.ServerCAs(),
	})
	require.NoError(e.t, err, "bug: generated client cert is not valid")
	return (*Certificate)(clientCert)
}

func (e *environment) NewServerCert(templateOverrides ...*x509.Certificate) *Certificate {
	caCert := e.CACert()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(e.t, err)

	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(e.t, err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		NotBefore:    now,
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}
	for _, override := range templateOverrides {
		tmpl.DNSNames = slices.Unique(append(tmpl.DNSNames, override.DNSNames...))
		tmpl.IPAddresses = slices.UniqueBy(append(tmpl.IPAddresses, override.IPAddresses...), net.IP.String)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert.Leaf, priv.Public(), caCert.PrivateKey)
	require.NoError(e.t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(e.t, err)
	e.debugf("provisioned server certificate for %v", cert.DNSNames)

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw, caCert.Leaf.Raw},
		PrivateKey:  priv,
		Leaf:        cert,
	}

	_, err = tlsCert.Leaf.Verify(x509.VerifyOptions{Roots: e.ServerCAs()})
	require.NoError(e.t, err, "bug: generated client cert is not valid")
	return (*Certificate)(tlsCert)
}

func (e *environment) SharedSecret() []byte {
	return bytes.Clone(e.sharedSecret[:])
}

func (e *environment) CookieSecret() []byte {
	return bytes.Clone(e.cookieSecret[:])
}

func (e *environment) NewDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	cc, err := grpc.NewGRPCClientConn(e.ctx, &grpc.Options{
		Address:      e.ports.Outbound.Value().String(),
		SignedJWTKey: e.sharedSecret[:],
	})
	e.require.NoError(err)
	return databroker.NewDataBrokerServiceClient(cc)
}

func (e *environment) Stop() {
	if b, ok := e.t.(*testing.B); ok {
		// when calling Stop() manually, ensure we aren't timing this
		b.StopTimer()
		defer b.StartTimer()
	}
	_, file, line, _ := runtime.Caller(1)
	e.cleanupOnce.Do(func() {
		e.cleanup(fmt.Errorf("%w (caller: %s:%d)", ErrCauseManualStop, file, line))
	})
}

func (e *environment) Pause() {
	e.t.Log("\x1b[31m*** test manually paused; continue with ctrl+c ***\x1b[0m")
	e.debugf(`
Ports:
  ProxyHTTP:    %s
  ProxyGRPC:    %s
  ProxySSH:     %s
  ProxyMetrics: %s
  EnvoyAdmin:   %s
  GRPC:         %s
  HTTP:         %s
  Outbound:     %s
  Metrics:      %s
  Debug:        %s
  ALPN:         %s
  `,
		e.ports.ProxyHTTP.Value(),
		e.ports.ProxyGRPC.Value(),
		e.ports.ProxySSH.Value(),
		e.ports.ProxyMetrics.Value(),
		e.ports.EnvoyAdmin.Value(),
		e.ports.GRPC.Value(),
		e.ports.HTTP.Value(),
		e.ports.Outbound.Value(),
		e.ports.Metrics.Value(),
		e.ports.Debug.Value(),
		e.ports.ALPN.Value())

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT)
	<-c
	signal.Stop(c)
	e.t.Log("\x1b[31mctrl+c received, continuing\x1b[0m")
}

func (e *environment) onTestCleanup() {
	e.cleanupOnce.Do(func() {
		e.cleanup(ErrCauseTestCleanup)
	})
}

func (e *environment) cleanup(cancelCause error) {
	e.debugf("stop: %s", cancelCause.Error())
	if e.t.Failed() {
		if e.pauseOnFailure {
			e.t.Log("\x1b[31m*** pausing on test failure; continue with ctrl+c ***\x1b[0m")
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT)
			<-c
			signal.Stop(c)
			e.t.Log("\x1b[31mctrl+c received, continuing\x1b[0m")
			signal.Stop(c)
		}
	}
	e.advanceState(Stopping)
	e.cancel(cancelCause)
	errs := []error{}
	if err := e.taskErrGroup.Wait(); err != nil {
		errs = append(errs, fmt.Errorf("error waiting for tasks: %w", err))
	}
	e.rootSpan.End()
	if err := trace.ShutdownContext(e.Context()); err != nil {
		errs = append(errs, fmt.Errorf("error shutting down trace context: %w", err))
	}
	e.advanceState(Stopped)
	// Wait for any additional callbacks created during stopped callbacks
	// (for consistency, we consider the stopped state to "end" here)
	e.stateChangeBlockers.Wait()
	e.debugf("stop: done")
	// err can be nil if e.g. the only task is the internal pomerium task, which
	// returns a nil error if it exits cleanly
	if err := errors.Join(errs...); err != nil {
		assert.ErrorIs(e.t, err, cancelCause)
	}
}

func (e *environment) Add(m Modifier) {
	e.t.Helper()
	caller := getCaller()
	e.debugf("Add: %T from %s", m, caller)
	switch e.GetState() {
	case NotRunning:
		for _, mod := range e.mods {
			if mod.Value == m {
				e.t.Fatalf("test bug: duplicate modifier added\nfirst added by: %s", mod.Caller)
			}
		}
		e.mods = append(e.mods, WithCaller[Modifier]{
			Caller: caller,
			Value:  m,
		})
		e.debugf("Add: state=NotRunning; calling Attach")
		m.Attach(e.Context())
	case Starting:
		panic("test bug: cannot call Add() before Start() has returned")
	case Running:
		e.debugf("Add: state=Running; calling ModifyConfig")
		e.src.ModifyConfig(e.Context(), m)
	case Stopped, Stopping:
		panic("test bug: cannot call Add() after Stop()")
	default:
		panic(fmt.Sprintf("unexpected environment state: %s", e.GetState()))
	}
}

func (e *environment) AddTask(t Task) {
	e.t.Helper()
	caller := getCaller()
	e.debugf("AddTask: %T from %s", t, caller)
	for _, task := range e.tasks {
		if task.Value == t {
			e.t.Fatalf("test bug: duplicate task added\nfirst added by: %s", task.Caller)
		}
	}
	e.tasks = append(e.tasks, WithCaller[Task]{
		Caller: getCaller(),
		Value:  t,
	})
}

func (e *environment) AddUpstream(up Upstream) {
	e.t.Helper()
	caller := getCaller()
	e.debugf("AddUpstream: %T from %s", up, caller)
	e.Add(up)
	e.AddTask(up)
}

// ReportError implements health.Provider.
func (e *environment) ReportError(_ health.Check, _ error, _ ...health.Attr) {
	// note: don't use e.t.Fatal here, it will deadlock
	// TODO : re-enable when health checks can be split across test envs
	// panic(fmt.Sprintf("%s: %v %v", check, err, attributes))
}

// ReportStatus implements health.Provider.
func (e *environment) ReportStatus(_ health.Check, _ health.Status, _ ...health.Attr) {}

func (e *environment) advanceState(newState EnvironmentState) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	if newState <= e.state {
		panic(fmt.Sprintf("internal test environment bug: changed state to <= current: newState=%s, current=%s", newState, e.state))
	}
	e.stateChangeBlockers.Wait()
	e.debugf("state %s -> %s", e.state.String(), newState.String())
	e.state = newState
	if len(e.stateChangeListeners[newState]) > 0 {
		e.debugf("notifying %d listeners of state change", len(e.stateChangeListeners[newState]))
		var wg sync.WaitGroup
		for _, listener := range e.stateChangeListeners[newState] {
			wg.Add(1)
			go func() {
				_, span := e.tracer.Start(e.Context(), "State Change Callback")
				span.SetAttributes(attribute.String("state", newState.String()))
				defer span.End()
				defer wg.Done()
				listener()
			}()
		}
		wg.Wait()
		e.debugf("done notifying state change listeners")
	}
}

func (e *environment) GetState() EnvironmentState {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	return e.state
}

func (e *environment) OnStateChanged(state EnvironmentState, callback func()) (cancel func() bool) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	_, file, line, _ := runtime.Caller(1)
	switch {
	case state < e.state:
		panic(fmt.Sprintf("test bug: OnStateChanged called with state %s which is < current state (%s)", state, e.sharedSecret))
	case state == e.state:
		e.stateChangeBlockers.Add(1)
		e.debugf("invoking callback for current state (state: %s, caller: %s:%d)", state.String(), file, line)
		go func() {
			defer func() {
				e.stateChangeBlockers.Done()
			}()
			callback()
		}()
		return func() bool { return false }
	default:
		canceled := &atomic.Bool{}
		e.stateChangeListeners[state] = append(e.stateChangeListeners[state], func() {
			if canceled.CompareAndSwap(false, true) {
				e.debugf("invoking state change callback (caller: %s:%d)", file, line)
				callback()
			}
		})
		return func() bool {
			e.debugf("stopped state change callback (state: %s, caller: %s:%d)", state.String(), file, line)
			return canceled.CompareAndSwap(false, true)
		}
	}
}

func getCaller(skip ...int) string {
	if len(skip) == 0 {
		skip = append(skip, 3)
	}
	callers := make([]uintptr, 8)
	runtime.Callers(skip[0], callers)
	frames := runtime.CallersFrames(callers)
	var caller string
	for {
		next, ok := frames.Next()
		if !ok {
			break
		}
		if path.Base(next.Function) == "testenv.(*environment).AddUpstream" {
			continue
		}
		caller = fmt.Sprintf("%s:%d", next.File, next.Line)
		break
	}
	return caller
}

func wildcardDomain(names []string) string {
	for _, name := range names {
		if name[0] == '*' {
			return name[2:]
		}
	}
	panic("test bug: no wildcard domain in certificate")
}

func isSilent(t testing.TB) bool {
	switch t.(type) {
	case *testing.B:
		return !slices.Contains(os.Args, "-test.v=true")
	default:
		return false
	}
}

type configSource struct {
	mu  sync.Mutex
	cfg *config.Config
	lis []config.ChangeListener
}

var _ config.Source = (*configSource)(nil)

// GetConfig implements config.Source.
func (src *configSource) GetConfig() *config.Config {
	src.mu.Lock()
	defer src.mu.Unlock()

	return src.cfg
}

// OnConfigChange implements config.Source.
func (src *configSource) OnConfigChange(_ context.Context, li config.ChangeListener) {
	src.mu.Lock()
	defer src.mu.Unlock()

	src.lis = append(src.lis, li)
}

// ModifyConfig updates the current configuration by applying a [Modifier].
func (src *configSource) ModifyConfig(ctx context.Context, m Modifier) {
	src.mu.Lock()
	defer src.mu.Unlock()

	m.Modify(src.cfg)
	for _, li := range src.lis {
		li(ctx, src.cfg)
	}
}

func newOtelConfigFromEnv(t testing.TB) otelconfig.Config {
	f, err := os.CreateTemp(t.TempDir(), "tmp-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.Close()
	cfg, err := config.NewFileOrEnvironmentSource(
		context.Background(), //nolint:usetesting
		f.Name(),
		version.FullVersion())
	require.NoError(t, err)
	return cfg.GetConfig().Options.Tracing
}

func GetDomainForAddress(addr netip.Addr) string {
	return strings.ReplaceAll(addr.String(), ".", "-") + ".sslip.io"
}

func GetSubDomainForAddress(subdomain string, addr netip.Addr) string {
	return subdomain + "-" + GetDomainForAddress(addr)
}
