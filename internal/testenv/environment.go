package testenv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/netutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// Environment is a lightweight integration test fixture that runs Pomerium
// in-process.
type Environment interface {
	// Context returns the environment's root context. This context holds a
	// top-level logger scoped to this environment. It will be canceled when
	// Stop() is called, or during test cleanup.
	Context() context.Context
	// TempDir returns a unique temp directory for this context. Calling this
	// function multiple times returns the same path.
	TempDir() string
	// ServerCAs returns a new [*x509.CertPool] containing the root CA certificate
	// used to sign the server cert and other test certificates.
	ServerCAs() *x509.CertPool
	// ServerCert returns the Pomerium server's certificate.
	ServerCert() *tls.Certificate

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

	// SubdomainURL returns a string [values.Value] which will contain a complete
	// URL for the given subdomain of the server's domain (given by its serving
	// certificate), including the 'https://' scheme and random http server port.
	// This value will only be resolved some time after Start() is called, and
	// can be used as the 'from' value for routes.
	SubdomainURL(subdomain string) values.Value[string]

	// NewLogRecorder returns a new [*LogRecorder] and starts capturing logs for
	// the Pomerium server and Envoy.
	NewLogRecorder(opts ...LogRecorderOption) *LogRecorder
}

type environment struct {
	t               testing.TB
	tempDir         string
	domain          string
	ports           Ports
	workspaceFolder string

	ctx         context.Context
	cancel      context.CancelCauseFunc
	cleanupOnce sync.Once
	logWriter   *log.MultiWriter

	mods         []WithCaller[Modifier]
	tasks        []WithCaller[Task]
	taskErrGroup *errgroup.Group
}

func New(t testing.TB) Environment {
	if testing.Short() {
		t.Helper()
		t.Skip("test environment disabled in short mode")
	}
	workspaceFolder, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(workspaceFolder, ".git")); err == nil {
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
	writer.Add(os.Stdout)
	logger := zerolog.New(writer).With().Timestamp().Logger().Level(zerolog.DebugLevel)

	ctx, cancel := context.WithCancelCause(logger.WithContext(context.Background()))
	taskErrGroup, ctx := errgroup.WithContext(ctx)

	e := &environment{
		t:       t,
		tempDir: t.TempDir(),
		ports: Ports{
			http: values.Deferred[int](),
		},
		workspaceFolder: workspaceFolder,
		ctx:             ctx,
		cancel:          cancel,
		logWriter:       writer,
		taskErrGroup:    taskErrGroup,
	}
	health.SetProvider(e)

	require.NoError(t, os.Mkdir(filepath.Join(e.tempDir, "certs"), 0o777))
	copyFile := func(src, dstRel string) {
		data, err := os.ReadFile(src)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(e.tempDir, dstRel), data, 0o666))
	}

	certsToCopy := []string{
		"trusted.pem",
		"trusted-key.pem",
		"ca.pem",
	}
	for _, crt := range certsToCopy {
		copyFile(filepath.Join(workspaceFolder, "integration/tpl/files", crt), filepath.Join("certs/", filepath.Base(crt)))
	}
	e.domain = wildcardDomain(e.ServerCert().Leaf.DNSNames)

	return e
}

type WithCaller[T any] struct {
	Caller string
	Value  T
}

type Ports struct {
	http values.MutableValue[int]
}

func (e *environment) TempDir() string {
	return e.tempDir
}

func (e *environment) Context() context.Context {
	return ContextWithEnv(e.ctx, e)
}

func (e *environment) SubdomainURL(subdomain string) values.Value[string] {
	return values.Bind(e.ports.http, func(port int) string {
		return fmt.Sprintf("https://%s.%s:%d", subdomain, e.domain, port)
	})
}

func (e *environment) ServerCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	caCert, err := os.ReadFile(filepath.Join(e.tempDir, "certs", "ca.pem"))
	require.NoError(e.t, err)
	pool.AppendCertsFromPEM(caCert)
	return pool
}

func (e *environment) ServerCert() *tls.Certificate {
	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(e.tempDir, "certs", "trusted.pem"),
		filepath.Join(e.tempDir, "certs", "trusted-key.pem"),
	)
	require.NoError(e.t, err)
	return &serverCert
}

// Used as the context's cancel cause during normal cleanup
var ErrCauseTestCleanup = errors.New("test cleanup")

// Used as the context's cancel cause when Stop() is called
var ErrCauseManualStop = errors.New("Stop() called")

func (e *environment) Start() {
	e.t.Cleanup(e.cleanup)

	cfg := &config.Config{
		Options: config.NewDefaultOptions(),
	}
	ports, err := netutil.AllocatePorts(7)
	require.NoError(e.t, err)
	port0, _ := strconv.Atoi(ports[0])
	e.ports.http.Resolve(port0)
	cfg.Options.LogLevel = config.LogLevelInfo
	cfg.Options.ProxyLogLevel = config.LogLevelInfo
	cfg.Options.Addr = fmt.Sprintf("127.0.0.1:%d", port0)
	cfg.Options.CertFile = filepath.Join(e.tempDir, "certs", "trusted.pem")
	cfg.Options.KeyFile = filepath.Join(e.tempDir, "certs", "trusted-key.pem")
	cfg.AllocatePorts(*(*[6]string)(ports[1:]))

	e.AddTask(TaskFunc(func(ctx context.Context) error {
		src := config.NewStaticSource(cfg)
		for _, mod := range e.mods {
			mod.Value.Modify(cfg)
			require.NoError(e.t, cfg.Options.Validate(), "invoking modifier resulted in an invalid configuration:\nadded by: "+mod.Caller)
		}
		return pomerium.Run(e.ctx, src)
	}))

	for i, task := range e.tasks {
		log.Ctx(e.ctx).Debug().Str("caller", task.Caller).Msgf("starting task %d", i)
		e.taskErrGroup.Go(func() error {
			defer log.Ctx(e.ctx).Debug().Str("caller", task.Caller).Msgf("task %d exited", i)
			return task.Value.Run(e.ctx)
		})
	}
}

func (e *environment) Stop() {
	e.cleanupOnce.Do(func() {
		e.cancel(ErrCauseManualStop)
		err := e.taskErrGroup.Wait()
		assert.ErrorIs(e.t, err, ErrCauseManualStop)
	})
}

func (e *environment) cleanup() {
	e.cleanupOnce.Do(func() {
		e.cancel(ErrCauseTestCleanup)
		err := e.taskErrGroup.Wait()
		assert.ErrorIs(e.t, err, ErrCauseTestCleanup)
	})
}

func (e *environment) Add(c Modifier) {
	e.t.Helper()
	for _, mod := range e.mods {
		if mod.Value == c {
			e.t.Fatalf("test bug: duplicate modifier added\nfirst added by: %s", mod.Caller)
		}
	}
	e.mods = append(e.mods, WithCaller[Modifier]{
		Caller: getCaller(),
		Value:  c,
	})
	c.Attach(e.Context())
}

func (e *environment) AddTask(r Task) {
	e.t.Helper()
	for _, task := range e.tasks {
		if task.Value == r {
			e.t.Fatalf("test bug: duplicate task added\nfirst added by: %s", task.Caller)
		}
	}
	e.tasks = append(e.tasks, WithCaller[Task]{
		Caller: getCaller(),
		Value:  r,
	})
}

func (e *environment) AddUpstream(up Upstream) {
	e.t.Helper()
	e.Add(up)
	e.AddTask(up)
}

// ReportError implements health.Provider.
func (e *environment) ReportError(check health.Check, err error, attributes ...health.Attr) {
	// note: don't use e.t.Fatal here, it will deadlock
	panic(fmt.Sprintf("%s: %v %v", check, err, attributes))
}

// ReportOK implements health.Provider.
func (e *environment) ReportOK(check health.Check, attributes ...health.Attr) {
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
