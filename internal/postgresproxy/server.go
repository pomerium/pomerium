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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

const defaultAuthorizationTimeout = 5 * time.Second

const maxPostgresMessageBodyLen = 16 * 1024 * 1024

var pgconnEnvKeys = []string{
	"PGHOST",
	"PGPORT",
	"PGDATABASE",
	"PGUSER",
	"PGPASSWORD",
	"PGPASSFILE",
	"PGSERVICE",
	"PGSERVICEFILE",
	"PGSSLMODE",
	"PGSSLCERT",
	"PGSSLKEY",
	"PGSSLROOTCERT",
	"PGSSLPASSWORD",
	"PGSSLNEGOTIATION",
	"PGAPPNAME",
	"PGCONNECT_TIMEOUT",
	"PGTARGETSESSIONATTRS",
	"PGTZ",
	"PGOPTIONS",
	"PGMINPROTOCOLVERSION",
	"PGMAXPROTOCOLVERSION",
}

var pgconnParseConfigMu sync.Mutex

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	active := map[net.Conn]struct{}{}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		mu.Lock()
		for conn := range active {
			_ = conn.Close()
		}
		mu.Unlock()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return ctx.Err()
			default:
				return err
			}
		}
		mu.Lock()
		active[conn] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				mu.Lock()
				delete(active, conn)
				mu.Unlock()
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

func (s *Server) Handle(ctx context.Context, raw net.Conn) (err error) {
	defer raw.Close()
	if s.Identity == nil {
		return errors.New("postgres proxy identity adapter is required")
	}
	if s.Policy == nil {
		return errors.New("postgres proxy policy adapter is required")
	}
	rec := s.Recorder
	if rec == nil {
		rec = noopRecorder{}
	}
	now := s.now

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
	if err := s.authorizeSession(ctx, session); err != nil {
		_ = writeError(client, "42501", "postgres session denied by policy", "session is not authorized")
		return err
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

	stopOnCancel := closeOnContextCancel(ctx, frontendConn, upstream)
	defer stopOnCancel()
	stopReauthorize := s.startPeriodicReauthorize(ctx, session, frontendConn, upstream)
	defer stopReauthorize()

	return s.relay(ctx, session, client, upstreamFrontend, upstream, rec)
}

func closeOnContextCancel(ctx context.Context, conns ...net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			for _, conn := range conns {
				_ = conn.Close()
			}
		case <-done:
		}
	}()
	return func() {
		close(done)
	}
}

func (s *Server) startPeriodicReauthorize(ctx context.Context, session *Session, clientConn net.Conn, upstreamConn net.Conn) func() {
	if s.ReauthorizeInterval <= 0 {
		return func() {}
	}
	reauthCtx, cancel := context.WithCancel(ctx)
	go func() {
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
	return cancel
}

type clientTLSState struct {
	ServerName         string
	ClientCertSHA256   string
	ClientCertPEM      string
	ClientCertChainPEM string
	ClientCertSubject  string
}

func (s *Server) acceptClientStartup(ctx context.Context, conn *bufferedConn) (net.Conn, pgproto3.FrontendMessage, clientTLSState, error) {
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	b, err := conn.r.Peek(1)
	if err != nil {
		return nil, nil, clientTLSState{}, err
	}
	if b[0] == 0x16 {
		return s.acceptDirectTLS(ctx, conn)
	}

	backend := pgproto3.NewBackend(conn, conn)
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
	if creds.Username == "" {
		creds.Username = session.DatabaseUser
	}
	if creds.Database == "" {
		creds.Database = session.Database
	}

	host, portString, err := net.SplitHostPort(target.Addr)
	if err != nil {
		return nil, nil, nil, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	cfg, err := parsePGConnConfigWithoutEnv()
	if err != nil {
		return nil, nil, nil, err
	}
	cfg.Host = host
	cfg.Port = uint16(port)
	cfg.User = creds.Username
	cfg.Password = creds.Password
	cfg.Database = creds.Database
	cfg.TLSConfig = target.TLSConfig
	cfg.Fallbacks = nil
	cfg.ChannelBinding = "disable"
	cfg.MinProtocolVersion = protocolString(protocol)
	cfg.MaxProtocolVersion = protocolString(protocol)
	cfg.ValidateConnect = nil
	cfg.RuntimeParams = make(map[string]string)
	if session.ApplicationName != "" {
		cfg.RuntimeParams["application_name"] = session.ApplicationName
	}
	cfg.KerberosSrvName = ""
	cfg.KerberosSpn = ""
	cfg.BuildFrontend = func(r io.Reader, w io.Writer) *pgproto3.Frontend {
		frontend := pgproto3.NewFrontend(r, w)
		frontend.SetMaxBodyLen(maxPostgresMessageBodyLen)
		return frontend
	}

	pgConn, err := pgconn.ConnectConfig(ctx, cfg)
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

func parsePGConnConfigWithoutEnv() (*pgconn.Config, error) {
	pgconnParseConfigMu.Lock()
	defer pgconnParseConfigMu.Unlock()

	type envValue struct {
		value string
		set   bool
	}
	saved := make(map[string]envValue, len(pgconnEnvKeys))
	for _, key := range pgconnEnvKeys {
		value, ok := os.LookupEnv(key)
		saved[key] = envValue{value: value, set: ok}
		if ok {
			_ = os.Unsetenv(key)
		}
	}
	defer func() {
		for _, key := range pgconnEnvKeys {
			if saved[key].set {
				_ = os.Setenv(key, saved[key].value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}()

	return pgconn.ParseConfig("host=127.0.0.1 port=5432 user=pomerium dbname=pomerium sslmode=disable target_session_attrs=any")
}

func (s *Server) authenticate(ctx context.Context, req AuthRequest) (*Session, error) {
	authCtx, cancel := s.withAuthorizationTimeout(ctx)
	defer cancel()
	return s.Identity.Authenticate(authCtx, req)
}

func (s *Server) authorizeSession(ctx context.Context, session *Session) error {
	authzCtx, cancel := s.withAuthorizationTimeout(ctx)
	defer cancel()
	return s.Policy.AuthorizeSession(authzCtx, session)
}

func (s *Server) authorizeQuery(ctx context.Context, req QueryRequest) (*Decision, error) {
	authzCtx, cancel := s.withAuthorizationTimeout(ctx)
	defer cancel()
	return s.Policy.AuthorizeQuery(authzCtx, req)
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

func protocolString(protocol uint32) string {
	switch protocol {
	case pgproto3.ProtocolVersion32:
		return "3.2"
	default:
		return "3.0"
	}
}

func (s *Server) forwardCancel(ctx context.Context, cancel *pgproto3.CancelRequest) error {
	upstreamCancel, ok := s.lookupCancelKey(cancel)
	if !ok {
		return nil
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", upstreamCancel.Target.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if upstreamCancel.Target.TLSConfig != nil {
		conn, err = startPostgresTLSForCancel(ctx, conn, upstreamCancel.Target.TLSConfig)
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
	var pidBytes [4]byte
	if _, err := rand.Read(pidBytes[:]); err != nil {
		return pgproto3.BackendKeyData{}, nil, err
	}
	pid := binary.BigEndian.Uint32(pidBytes[:])
	if pid == 0 {
		pid = 1
	}
	secret := make([]byte, 4)
	if _, err := rand.Read(secret); err != nil {
		return pgproto3.BackendKeyData{}, nil, err
	}
	proxy := pgproto3.BackendKeyData{ProcessID: pid, SecretKey: secret}
	s.cancelMu.Lock()
	if s.cancelKeys == nil {
		s.cancelKeys = map[string]pgproto3CancelRequest{}
	}
	key := cancelKey(proxy.ProcessID, proxy.SecretKey)
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
