package postgresproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

const (
	defaultAuthorizationTimeout = 5 * time.Second
	defaultStartupTimeout       = 30 * time.Second
	defaultUpstreamTimeout      = 10 * time.Second
	defaultCancelTimeout        = 10 * time.Second
	defaultIdleTimeout          = 30 * time.Minute
	defaultMaxConnectionAge     = time.Hour
	defaultMaxConnections       = 1024
)

const maxPostgresMessageBodyLen = 16 * 1024 * 1024

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	active := map[net.Conn]struct{}{}
	stopping := false
	shutdown := func() {
		mu.Lock()
		if stopping {
			mu.Unlock()
			return
		}
		stopping = true
		_ = ln.Close()
		for conn := range active {
			_ = conn.Close()
		}
		mu.Unlock()
	}
	stopShutdown := context.AfterFunc(ctx, shutdown)
	defer stopShutdown()
	defer func() {
		shutdown()
		wg.Wait()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if !s.acquireConnection() {
			_ = conn.Close()
			continue
		}
		mu.Lock()
		if stopping {
			mu.Unlock()
			s.releaseConnection()
			_ = conn.Close()
			continue
		}
		active[conn] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				mu.Lock()
				delete(active, conn)
				mu.Unlock()
				s.releaseConnection()
			}()
			defer func() {
				if recover() != nil {
					_ = conn.Close()
				}
			}()
			_ = s.Handle(ctx, conn)
		}()
	}
}

func (s *Server) acquireConnection() bool {
	limit := s.MaxConnections
	if limit <= 0 {
		limit = defaultMaxConnections
	}
	for {
		active := s.active.Load()
		if active >= int64(limit) {
			return false
		}
		if s.active.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func (s *Server) releaseConnection() {
	s.active.Add(-1)
}

func (s *Server) Handle(ctx context.Context, raw net.Conn) (err error) {
	defer raw.Close()
	if s.Identity == nil {
		return errors.New("postgres proxy identity adapter is required")
	}
	if s.Policy == nil {
		return errors.New("postgres proxy policy adapter is required")
	}
	now := s.now
	acceptedAt := now()
	_ = raw.SetDeadline(acceptedAt.Add(s.startupTimeout()))

	conn := newBufferedConn(raw)
	frontendConn, startup, tlsState, err := s.acceptClientStartup(ctx, conn)
	if err != nil {
		return err
	}
	if cancel, ok := startup.(*pgproto3.CancelRequest); ok {
		return s.forwardCancel(ctx, cancel)
	}
	sm, ok := startup.(*pgproto3.StartupMessage)
	if !ok {
		return fmt.Errorf("unexpected startup message %T", startup)
	}
	client := pgproto3.NewBackend(frontendConn, frontendConn)
	client.SetMaxBodyLen(maxPostgresMessageBodyLen)
	if _, err := protocolString(sm.ProtocolVersion); err != nil {
		_ = writeError(client, "08P01", "unsupported postgres protocol version", "protocol version is not supported")
		return err
	}

	params := cloneStringMap(sm.Parameters)
	authReq := AuthRequest{
		ClientAddr:         raw.RemoteAddr(),
		ServerName:         tlsState.ServerName,
		ClientCertSHA256:   tlsState.ClientCertSHA256,
		ClientCertPEM:      tlsState.ClientCertPEM,
		ClientCertChainPEM: tlsState.ClientCertChainPEM,
		ClientCertSubject:  tlsState.ClientCertSubject,
		Database:           params["database"],
		Username:           params["user"],
		ApplicationName:    params["application_name"],
		ProtocolVersion:    sm.ProtocolVersion,
		Parameters:         params,
	}
	session, err := s.authenticate(ctx, authReq)
	if err != nil {
		_ = writeError(client, "28000", "postgres identity denied connection", "authentication failed")
		return err
	}
	if session == nil {
		err := errors.New("postgres identity returned nil session")
		_ = writeError(client, "28000", "postgres identity denied connection", "authentication failed")
		return err
	}
	if session.StartedAt.IsZero() {
		session.StartedAt = now()
	}
	connectionDeadline := acceptedAt.Add(s.maxConnectionAge())
	if !session.ExpiresAt.IsZero() {
		if !session.ExpiresAt.After(now()) {
			err := errors.New("postgres authenticated session has expired")
			_ = writeError(client, "28000", "postgres identity denied connection", "authentication failed")
			return err
		}
		if session.ExpiresAt.Before(connectionDeadline) {
			connectionDeadline = session.ExpiresAt
		}
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithDeadline(ctx, connectionDeadline)
	defer cancel()
	if err := s.authorizeSession(ctx, session); err != nil {
		_ = writeError(client, "42501", "postgres session denied by policy", "session is not authorized")
		return err
	}
	var rec Recorder = noopRecorder{}
	if s.relayForTest != nil {
		if s.queryPolicyForTest == nil {
			return errors.New("postgres governed relay test requires query policy")
		}
		if s.recorderForTest != nil {
			rec = s.recorderForTest
		}
		if err := rec.BeginSession(ctx, session); err != nil {
			_ = writeError(client, "58000", "postgres recording failed to start", "recording is required but unavailable")
			return err
		}
		defer func() {
			if endErr := rec.EndSession(context.WithoutCancel(ctx), session, err); endErr != nil {
				err = errors.Join(err, endErr)
			}
		}()
	}

	upstream, upstreamFrontend, unregisterCancel, err := s.connectUpstream(ctx, session, sm.ProtocolVersion, client)
	if err != nil {
		_ = writeError(client, "08001", "postgres upstream connection failed", "upstream connection failed")
		return err
	}
	defer upstream.Close()
	defer unregisterCancel()
	if err := flush(client); err != nil {
		return err
	}
	activity := &connectionActivity{
		client:   frontendConn,
		upstream: upstream,
		idle:     s.idleTimeout(),
		absolute: connectionDeadline,
		now:      now,
	}
	activity.waitForClient()
	ctx = context.WithValue(ctx, connectionActivityKey{}, activity)

	stopOnCancel := closeOnContextCancel(ctx, frontendConn, upstream)
	defer stopOnCancel()
	stopReauthorize := s.startPeriodicReauthorize(ctx, session, frontendConn, upstream)
	defer stopReauthorize()

	if s.relayForTest != nil {
		return s.relayForTest(ctx, session, client, frontendConn, upstreamFrontend, upstream, rec)
	}
	return s.relay(ctx, session, client, frontendConn, upstreamFrontend, upstream)
}

func closeOnContextCancel(ctx context.Context, conns ...net.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
		close(done)
	})
	return func() {
		if stop() {
			close(done)
		}
		<-done
	}
}

func (s *Server) startPeriodicReauthorize(ctx context.Context, session *Session, clientConn net.Conn, upstreamConn net.Conn) func() {
	if s.ReauthorizeInterval <= 0 {
		return func() {}
	}
	reauthCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if recover() != nil {
				_ = clientConn.Close()
				_ = upstreamConn.Close()
				cancel()
			}
		}()
		ticker := time.NewTicker(s.ReauthorizeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-reauthCtx.Done():
				return
			case <-ticker.C:
				if err := s.reauthorize(reauthCtx, session); err != nil {
					_ = clientConn.Close()
					_ = upstreamConn.Close()
					cancel()
					return
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

type clientTLSState struct {
	ServerName         string
	ClientCertSHA256   string
	ClientCertPEM      string
	ClientCertChainPEM string
	ClientCertSubject  string
}

func (s *Server) acceptClientStartup(ctx context.Context, conn *bufferedConn) (net.Conn, pgproto3.FrontendMessage, clientTLSState, error) {
	b, err := conn.r.Peek(1)
	if err != nil {
		return nil, nil, clientTLSState{}, err
	}
	if b[0] == 0x16 {
		return s.acceptDirectTLS(ctx, conn)
	}

	backend := pgproto3.NewBackend(conn, conn)
	backend.SetMaxBodyLen(maxPostgresMessageBodyLen)
	for {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, nil, clientTLSState{}, err
		}
		switch msg.(type) {
		case *pgproto3.SSLRequest:
			if s.DownstreamTLS == nil {
				if _, err := conn.Write([]byte{'N'}); err != nil {
					return nil, nil, clientTLSState{}, err
				}
				continue
			}
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return nil, nil, clientTLSState{}, err
			}
			tlsConn := tls.Server(conn, s.DownstreamTLS)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, nil, clientTLSState{}, err
			}
			tlsBackend := pgproto3.NewBackend(tlsConn, tlsConn)
			tlsBackend.SetMaxBodyLen(maxPostgresMessageBodyLen)
			startup, err := tlsBackend.ReceiveStartupMessage()
			return tlsConn, startup, tlsClientState(tlsConn), err
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, nil, clientTLSState{}, err
			}
		case *pgproto3.CancelRequest:
			return conn, msg, clientTLSState{}, nil
		default:
			if s.DownstreamTLS != nil {
				return nil, nil, clientTLSState{}, errors.New("postgres client TLS is required")
			}
			return conn, msg, clientTLSState{}, nil
		}
	}
}

func (s *Server) acceptDirectTLS(ctx context.Context, conn *bufferedConn) (net.Conn, pgproto3.FrontendMessage, clientTLSState, error) {
	if s.DownstreamTLS == nil {
		return nil, nil, clientTLSState{}, errors.New("direct TLS received but downstream TLS is not configured")
	}
	tlsConn := tls.Server(conn, s.DownstreamTLS)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, clientTLSState{}, err
	}
	backend := pgproto3.NewBackend(tlsConn, tlsConn)
	backend.SetMaxBodyLen(maxPostgresMessageBodyLen)
	startup, err := backend.ReceiveStartupMessage()
	return tlsConn, startup, tlsClientState(tlsConn), err
}

func tlsClientState(conn *tls.Conn) clientTLSState {
	state := conn.ConnectionState()
	out := clientTLSState{ServerName: state.ServerName}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		sum := sha256.Sum256(cert.Raw)
		out.ClientCertSHA256 = hex.EncodeToString(sum[:])
		out.ClientCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		out.ClientCertSubject = cert.Subject.String()
		var chain strings.Builder
		for _, cert := range state.PeerCertificates {
			_, _ = chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		}
		out.ClientCertChainPEM = chain.String()
	}
	return out
}

func (s *Server) connectUpstream(ctx context.Context, session *Session, protocol uint32, client *pgproto3.Backend) (net.Conn, *pgproto3.Frontend, func(), error) {
	target := &UpstreamTarget{
		Addr:      s.UpstreamAddr,
		TLSConfig: s.UpstreamTLSConfig,
	}
	if s.UpstreamResolver != nil {
		var err error
		resolveCtx, cancel := s.withAuthorizationTimeout(ctx)
		target, err = s.UpstreamResolver.ResolveUpstream(resolveCtx, session)
		cancel()
		if err != nil {
			return nil, nil, nil, err
		}
	}
	if target == nil || target.Addr == "" {
		return nil, nil, nil, errors.New("postgres upstream address is required")
	}
	cfg, err := preparePGConnConfig(target, session, protocol, s.upstreamTimeout())
	if err != nil {
		return nil, nil, nil, err
	}

	// Fetch managed credentials, and therefore re-verify the Enterprise
	// capability, only after all non-secret dial preparation is complete.
	credsCtx, cancel := s.withAuthorizationTimeout(ctx)
	credsPtr, err := s.Identity.UpstreamCredentials(credsCtx, session)
	cancel()
	if err != nil {
		return nil, nil, nil, err
	}
	if credsPtr == nil {
		return nil, nil, nil, errors.New("postgres upstream credentials are required")
	}
	creds := *credsPtr
	if creds.Username == "" || creds.Password == "" || creds.Database == "" {
		return nil, nil, nil, errors.New("postgres managed upstream credentials are incomplete")
	}
	cfg.User = creds.Username
	cfg.Password = creds.Password
	cfg.Database = creds.Database

	connectCtx, connectCancel := context.WithTimeout(ctx, s.upstreamTimeout())
	pgConn, err := pgconn.ConnectConfig(connectCtx, cfg)
	connectCancel()
	if err != nil {
		return nil, nil, nil, err
	}
	hijacked, err := pgConn.Hijack()
	if err != nil {
		_ = pgConn.Close(ctx)
		return nil, nil, nil, err
	}
	proxyKey, unregisterCancel, err := s.registerCancelKey(pgproto3.BackendKeyData{
		ProcessID: hijacked.PID,
		SecretKey: hijacked.SecretKey,
	}, target)
	if err != nil {
		_ = hijacked.Conn.Close()
		return nil, nil, nil, err
	}
	client.Send(&pgproto3.AuthenticationOk{})
	for k, v := range hijacked.ParameterStatuses {
		client.Send(&pgproto3.ParameterStatus{Name: k, Value: v})
	}
	client.Send(&proxyKey)
	client.Send(&pgproto3.ReadyForQuery{TxStatus: hijacked.TxStatus})
	return hijacked.Conn, hijacked.Frontend, unregisterCancel, nil
}

func preparePGConnConfig(target *UpstreamTarget, session *Session, protocol uint32, connectTimeout time.Duration) (*pgconn.Config, error) {
	if target == nil || target.Addr == "" {
		return nil, errors.New("postgres upstream address is required")
	}
	host, portString, err := net.SplitHostPort(target.Addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, err
	}
	cfg, err := parsePGConnConfig()
	if err != nil {
		return nil, err
	}
	cfg.Host = host
	cfg.Port = uint16(port)
	cfg.User = ""
	cfg.Password = ""
	cfg.Database = ""
	cfg.TLSConfig = target.TLSConfig
	cfg.Fallbacks = nil
	cfg.ChannelBinding = "disable"
	cfg.SSLNegotiation = "postgres"
	protocolVersion, err := protocolString(protocol)
	if err != nil {
		return nil, err
	}
	cfg.MinProtocolVersion = protocolVersion
	cfg.MaxProtocolVersion = protocolVersion
	cfg.ValidateConnect = nil
	cfg.AfterConnect = nil
	cfg.AfterNetConnect = nil
	cfg.OnNotice = nil
	cfg.OnNotification = nil
	cfg.OAuthTokenProvider = nil
	cfg.ConnectTimeout = connectTimeout
	dialer := new(net.Dialer)
	cfg.DialFunc = dialer.DialContext
	cfg.LookupFunc = net.DefaultResolver.LookupHost
	cfg.RuntimeParams = make(map[string]string)
	if session != nil && session.ApplicationName != "" {
		cfg.RuntimeParams["application_name"] = session.ApplicationName
	}
	cfg.KerberosSrvName = ""
	cfg.KerberosSpn = ""
	cfg.BuildFrontend = func(r io.Reader, w io.Writer) *pgproto3.Frontend {
		frontend := pgproto3.NewFrontend(r, w)
		frontend.SetMaxBodyLen(maxPostgresMessageBodyLen)
		return frontend
	}
	return cfg, nil
}

func parsePGConnConfig() (*pgconn.Config, error) {
	// pgconn requires Config to originate from ParseConfig. Every security-
	// relevant field is overwritten by connectUpstream before use; parsing an
	// explicit inert placeholder avoids mutating the process-wide environment.
	return pgconn.ParseConfig("host=127.0.0.1 port=5432 user=pomerium dbname=pomerium sslmode=disable target_session_attrs=any")
}

func (s *Server) authenticate(ctx context.Context, req AuthRequest) (*Session, error) {
	authCtx, cancel := s.withAuthorizationTimeout(ctx)
	defer cancel()
	session, err := s.Identity.Authenticate(authCtx, req)
	if err == nil && session != nil {
		session.markIdentityValidated()
	}
	return session, err
}

func (s *Server) authorizeSession(ctx context.Context, session *Session) error {
	authzCtx, cancel := s.withAuthorizationTimeout(ctx)
	defer cancel()
	return s.Policy.AuthorizeSession(authzCtx, session)
}

func (s *Server) authorizeQuery(ctx context.Context, req QueryRequest) (*Decision, error) {
	if s.queryPolicyForTest == nil {
		return nil, errors.New("postgres governed relay query policy is unavailable")
	}
	authzCtx, cancel := s.withAuthorizationTimeout(ctx)
	defer cancel()
	return s.queryPolicyForTest.AuthorizeQuery(authzCtx, req)
}

func (s *Server) reauthorize(ctx context.Context, session *Session) error {
	reauthCtx, cancel := s.withAuthorizationTimeout(ctx)
	defer cancel()
	return s.Identity.Reauthorize(reauthCtx, cloneSession(session))
}

func (s *Server) withAuthorizationTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := s.AuthorizationTimeout
	if timeout <= 0 {
		timeout = defaultAuthorizationTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func protocolString(protocol uint32) (string, error) {
	switch protocol {
	case pgproto3.ProtocolVersion30:
		return "3.0", nil
	}
	return "", fmt.Errorf("unsupported postgres protocol version %d", protocol)
}

func (s *Server) forwardCancel(ctx context.Context, cancel *pgproto3.CancelRequest) error {
	upstreamCancel, ok := s.lookupCancelKey(cancel)
	if !ok {
		return nil
	}
	cancelCtx, stop := context.WithTimeout(ctx, s.cancelTimeout())
	defer stop()
	var d net.Dialer
	conn, err := d.DialContext(cancelCtx, "tcp", upstreamCancel.Target.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := cancelCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if upstreamCancel.Target.TLSConfig != nil {
		conn, err = startPostgresTLSForCancel(cancelCtx, conn, upstreamCancel.Target.TLSConfig)
		if err != nil {
			return err
		}
		defer conn.Close()
	}
	buf, err := (&pgproto3.CancelRequest{
		ProcessID: upstreamCancel.ProcessID,
		SecretKey: upstreamCancel.SecretKey,
	}).Encode(nil)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf)
	return err
}

func startPostgresTLSForCancel(ctx context.Context, conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	buf, err := (&pgproto3.SSLRequest{}).Encode(nil)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}
	var response [1]byte
	if _, err := conn.Read(response[:]); err != nil {
		return nil, err
	}
	if response[0] != 'S' {
		return nil, errors.New("postgres upstream did not accept TLS for cancel request")
	}
	tlsConn := tls.Client(conn, cfg.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func (s *Server) registerCancelKey(upstream pgproto3.BackendKeyData, target *UpstreamTarget) (pgproto3.BackendKeyData, func(), error) {
	s.cancelMu.Lock()
	if s.cancelKeys == nil {
		s.cancelKeys = map[string]pgproto3CancelRequest{}
	}
	var proxy pgproto3.BackendKeyData
	var key string
	for range 16 {
		var randomKey [8]byte
		if _, err := io.ReadFull(s.randomSource(), randomKey[:]); err != nil {
			s.cancelMu.Unlock()
			return pgproto3.BackendKeyData{}, nil, err
		}
		pid := binary.BigEndian.Uint32(randomKey[:4])
		if pid == 0 {
			pid = 1
		}
		proxy = pgproto3.BackendKeyData{ProcessID: pid, SecretKey: append([]byte(nil), randomKey[4:]...)}
		key = cancelKey(proxy.ProcessID, proxy.SecretKey)
		if _, exists := s.cancelKeys[key]; !exists {
			s.cancelKeys[key] = pgproto3CancelRequest{
				ProcessID: upstream.ProcessID,
				SecretKey: append([]byte(nil), upstream.SecretKey...),
				Target:    cloneUpstreamTarget(target),
			}
			s.cancelMu.Unlock()
			return proxy, func() {
				s.cancelMu.Lock()
				delete(s.cancelKeys, key)
				s.cancelMu.Unlock()
			}, nil
		}
	}
	s.cancelMu.Unlock()
	return pgproto3.BackendKeyData{}, nil, errors.New("postgres cancel key collision limit exceeded")
}

func (s *Server) randomSource() io.Reader {
	if s.random != nil {
		return s.random
	}
	return rand.Reader
}

func (s *Server) lookupCancelKey(cancel *pgproto3.CancelRequest) (*pgproto3CancelRequest, bool) {
	s.cancelMu.Lock()
	upstream, ok := s.cancelKeys[cancelKey(cancel.ProcessID, cancel.SecretKey)]
	s.cancelMu.Unlock()
	if !ok {
		return nil, false
	}
	return &pgproto3CancelRequest{
		ProcessID: upstream.ProcessID,
		SecretKey: append([]byte(nil), upstream.SecretKey...),
		Target:    cloneUpstreamTarget(&upstream.Target),
	}, true
}

func cloneUpstreamTarget(target *UpstreamTarget) UpstreamTarget {
	if target == nil {
		return UpstreamTarget{}
	}
	out := *target
	if target.TLSConfig != nil {
		out.TLSConfig = target.TLSConfig.Clone()
	}
	return out
}

func cancelKey(pid uint32, secret []byte) string {
	return fmt.Sprintf("%d:%s", pid, hex.EncodeToString(secret))
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) startupTimeout() time.Duration {
	if s.StartupTimeout > 0 {
		return s.StartupTimeout
	}
	return defaultStartupTimeout
}

func (s *Server) upstreamTimeout() time.Duration {
	if s.UpstreamTimeout > 0 {
		return s.UpstreamTimeout
	}
	return defaultUpstreamTimeout
}

func (s *Server) cancelTimeout() time.Duration {
	if s.CancelTimeout > 0 {
		return s.CancelTimeout
	}
	return defaultCancelTimeout
}

func (s *Server) idleTimeout() time.Duration {
	if s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return defaultIdleTimeout
}

func (s *Server) maxConnectionAge() time.Duration {
	if s.MaxConnectionAge > 0 {
		return s.MaxConnectionAge
	}
	return defaultMaxConnectionAge
}

type connectionActivityKey struct{}

type connectionWorkKind uint8

const (
	connectionWorkQuery connectionWorkKind = iota + 1
	connectionWorkExecute
	connectionWorkSync
	connectionWorkFunctionCall
)

type connectionCopyState uint8

const (
	connectionCopyNone connectionCopyState = iota
	connectionCopyInput
	connectionCopyFinishing
)

type connectionWork struct {
	kind      connectionWorkKind
	cycleID   uint64
	copyState connectionCopyState
}

type connectionCycle struct {
	id     uint64
	failed bool
}

type connectionActivity struct {
	mu              sync.Mutex
	client          net.Conn
	upstream        net.Conn
	idle            time.Duration
	absolute        time.Time
	now             func() time.Time
	nextCycleID     uint64
	frontendCycleID uint64
	cycles          []connectionCycle
	work            []connectionWork
}

func (a *connectionActivity) waitForClient() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.waitForClientLocked()
}

func (a *connectionActivity) waitForClientLocked() {
	deadline := a.now().Add(a.idle)
	if deadline.After(a.absolute) {
		deadline = a.absolute
	}
	if a.client != nil {
		_ = a.client.SetDeadline(deadline)
	}
	if a.upstream != nil {
		_ = a.upstream.SetDeadline(a.absolute)
	}
}

func (a *connectionActivity) activeLocked() {
	if a.client != nil {
		_ = a.client.SetDeadline(a.absolute)
	}
	if a.upstream != nil {
		_ = a.upstream.SetDeadline(a.absolute)
	}
}

func (a *connectionActivity) ensureFrontendCycleLocked() uint64 {
	if a.frontendCycleID != 0 {
		return a.frontendCycleID
	}
	a.nextCycleID++
	a.frontendCycleID = a.nextCycleID
	a.cycles = append(a.cycles, connectionCycle{id: a.frontendCycleID})
	return a.frontendCycleID
}

func (a *connectionActivity) cycleFailedLocked(id uint64) bool {
	if id == 0 {
		return false
	}
	for i := range a.cycles {
		if a.cycles[i].id == id {
			return a.cycles[i].failed
		}
	}
	return false
}

func (a *connectionActivity) appendWorkLocked(kind connectionWorkKind, cycleID uint64) {
	if !a.cycleFailedLocked(cycleID) {
		a.work = append(a.work, connectionWork{kind: kind, cycleID: cycleID})
	}
}

func (a *connectionActivity) frontendReceived(msg pgproto3.FrontendMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear the client-wait deadline before reauthorization and forwarding. Once
	// the message is forwarded, frontendForwarded restores it unless this
	// message created actual upstream work.
	a.activeLocked()

	switch msg.(type) {
	case *pgproto3.Query:
		cycleID := a.frontendCycleID
		a.appendWorkLocked(connectionWorkQuery, cycleID)
		if cycleID != 0 {
			a.frontendCycleID = 0
		}
	case *pgproto3.FunctionCall:
		cycleID := a.frontendCycleID
		a.appendWorkLocked(connectionWorkFunctionCall, cycleID)
		if cycleID != 0 {
			a.frontendCycleID = 0
		}
	case *pgproto3.Parse, *pgproto3.Bind, *pgproto3.Describe, *pgproto3.Close:
		a.ensureFrontendCycleLocked()
	case *pgproto3.Execute:
		cycleID := a.ensureFrontendCycleLocked()
		a.appendWorkLocked(connectionWorkExecute, cycleID)
	case *pgproto3.Flush:
		// Flush belongs to an existing extended cycle, but a standalone Flush
		// neither starts work nor promises a response boundary.
	case *pgproto3.Sync:
		cycleID := a.ensureFrontendCycleLocked()
		// A failed cycle still requires Sync before the backend returns to
		// ReadyForQuery, so this boundary is always retained.
		a.work = append(a.work, connectionWork{kind: connectionWorkSync, cycleID: cycleID})
		a.frontendCycleID = 0
	case *pgproto3.CopyDone, *pgproto3.CopyFail:
		if len(a.work) > 0 && a.work[0].copyState == connectionCopyInput {
			a.work[0].copyState = connectionCopyFinishing
		}
	}
}

func (a *connectionActivity) frontendForwarded() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.applyDeadlineLocked()
}

func (a *connectionActivity) backendForwarded(msg pgproto3.BackendMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch msg.(type) {
	case *pgproto3.ReadyForQuery:
		a.completeReadyLocked()
	case *pgproto3.CommandComplete, *pgproto3.PortalSuspended, *pgproto3.EmptyQueryResponse:
		a.completeExecuteLocked()
	case *pgproto3.ErrorResponse:
		a.failCurrentWorkLocked()
	case *pgproto3.CopyInResponse, *pgproto3.CopyBothResponse:
		a.beginCopyInputLocked()
	default:
		return
	}
	a.applyDeadlineLocked()
}

func (a *connectionActivity) applyDeadlineLocked() {
	if len(a.work) == 0 || a.work[0].copyState == connectionCopyInput {
		a.waitForClientLocked()
		return
	}
	a.activeLocked()
}

func (a *connectionActivity) completeExecuteLocked() {
	if len(a.work) == 0 || a.work[0].kind != connectionWorkExecute {
		return
	}
	a.work = a.work[1:]
}

func (a *connectionActivity) completeReadyLocked() {
	for i, work := range a.work {
		switch work.kind {
		case connectionWorkQuery, connectionWorkSync, connectionWorkFunctionCall:
			a.work = a.work[i+1:]
			if work.cycleID != 0 {
				a.removeCycleLocked(work.cycleID)
			}
			return
		}
	}
	if len(a.cycles) > 0 && a.cycles[0].failed {
		a.removeCycleLocked(a.cycles[0].id)
	}
}

func (a *connectionActivity) failCurrentWorkLocked() {
	if len(a.work) > 0 && a.work[0].cycleID == 0 {
		switch a.work[0].kind {
		case connectionWorkQuery:
			// Simple Query errors are followed by ReadyForQuery.
			return
		case connectionWorkFunctionCall:
			// FunctionCallResponse and ErrorResponse are both followed by
			// ReadyForQuery, which is the client-wait boundary.
			return
		}
	}
	if len(a.cycles) == 0 {
		return
	}
	cycleID := a.cycles[0].id
	a.cycles[0].failed = true
	kept := a.work[:0]
	for _, work := range a.work {
		if work.cycleID == cycleID && work.kind != connectionWorkSync {
			continue
		}
		kept = append(kept, work)
	}
	a.work = kept
}

func (a *connectionActivity) beginCopyInputLocked() {
	if len(a.work) == 0 {
		return
	}
	switch a.work[0].kind {
	case connectionWorkQuery, connectionWorkExecute:
		a.work[0].copyState = connectionCopyInput
	}
}

func (a *connectionActivity) removeCycleLocked(cycleID uint64) {
	if a.frontendCycleID == cycleID {
		a.frontendCycleID = 0
	}
	for i := range a.cycles {
		if a.cycles[i].id == cycleID {
			a.cycles = append(a.cycles[:i], a.cycles[i+1:]...)
			return
		}
	}
}

func connectionActivityFromContext(ctx context.Context) *connectionActivity {
	if activity, ok := ctx.Value(connectionActivityKey{}).(*connectionActivity); ok {
		return activity
	}
	return nil
}

func writeError(client *pgproto3.Backend, code, message, detail string) error {
	return writeErrorWithTxStatus(client, code, message, detail, 'I')
}

func writeErrorWithTxStatus(client *pgproto3.Backend, code, message, detail string, txStatus byte) error {
	if err := writeErrorResponse(client, code, message, detail); err != nil {
		return err
	}
	return writeReadyForQuery(client, txStatus)
}

func writeErrorResponse(client *pgproto3.Backend, code, message, detail string) error {
	client.Send(&pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     code,
		Message:  message,
		Detail:   detail,
	})
	return flush(client)
}

func writeReadyForQuery(client *pgproto3.Backend, txStatus byte) error {
	if txStatus == 0 {
		txStatus = 'I'
	}
	client.Send(&pgproto3.ReadyForQuery{TxStatus: txStatus})
	return flush(client)
}

func flush(client *pgproto3.Backend) error {
	return client.Flush()
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func parseCommandRows(tag string) int {
	fields := strings.Fields(tag)
	if len(fields) == 0 {
		return 0
	}
	last := fields[len(fields)-1]
	n, _ := strconv.Atoi(last)
	return n
}
