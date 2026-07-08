package postgresproxy

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

type Server struct {
	UpstreamAddr         string
	UpstreamTLSConfig    *tls.Config
	UpstreamResolver     UpstreamResolver
	DownstreamTLS        *tls.Config
	ReauthorizeInterval  time.Duration
	AuthorizationTimeout time.Duration
	Identity             Identity
	Policy               Policy
	Recorder             Recorder
	Now                  func() time.Time

	cancelMu   sync.Mutex
	cancelKeys map[string]pgproto3CancelRequest
}

type pgproto3CancelRequest struct {
	ProcessID uint32
	SecretKey []byte
	Target    UpstreamTarget
}

type Identity interface {
	Authenticate(context.Context, AuthRequest) (*Session, error)
	Reauthorize(context.Context, *Session) error
	UpstreamCredentials(context.Context, *Session) (*UpstreamCredentials, error)
}

type UpstreamResolver interface {
	ResolveUpstream(context.Context, *Session) (*UpstreamTarget, error)
}

type UpstreamTarget struct {
	Addr      string
	TLSConfig *tls.Config
}

type Policy interface {
	AuthorizeSession(context.Context, *Session) error
	AuthorizeQuery(context.Context, QueryRequest) (*Decision, error)
}

type Recorder interface {
	BeginSession(context.Context, *Session) error
	RecordQuery(context.Context, QueryRecord) error
	EndSession(context.Context, *Session, error) error
}

type AuthRequest struct {
	ClientAddr         net.Addr
	ServerName         string
	ClientCertSHA256   string
	ClientCertPEM      string
	ClientCertChainPEM string
	ClientCertSubject  string
	Database           string
	Username           string
	ApplicationName    string
	ProtocolVersion    uint32
	Parameters         map[string]string
}

type Session struct {
	ID                string
	PomeriumSessionID string
	SessionBindingID  string
	UserID            string
	RouteID           string
	Hostname          string
	Database          string
	DatabaseUser      string
	ApplicationName   string
	ClientAddr        string
	ClientCertSHA256  string
	ClientCertPEM     string
	StartedAt         time.Time
}

type UpstreamCredentials struct {
	Username string
	Password string
	Database string
}

type QueryRequest struct {
	Session        *Session
	Protocol       QueryProtocol
	SQL            string
	StatementClass string
	Portal         string
	Statement      string
	ParameterCount int
	StartedAt      time.Time
}

type Decision struct {
	Action DecisionAction
	Reason string
	RowCap int
}

type DecisionAction string

const (
	DecisionAllow  DecisionAction = "allow"
	DecisionDeny   DecisionAction = "deny"
	DecisionRowCap DecisionAction = "row_cap"
	DecisionStepUp DecisionAction = "step_up"
)

type QueryProtocol string

const (
	QueryProtocolSimple       QueryProtocol = "simple"
	QueryProtocolExtended     QueryProtocol = "extended"
	QueryProtocolFunctionCall QueryProtocol = "function_call"
)

type QueryRecord struct {
	SessionID          string         `json:"session_id"`
	Protocol           QueryProtocol  `json:"protocol"`
	SQL                string         `json:"sql"`
	StatementClass     string         `json:"statement_class"`
	Decision           DecisionAction `json:"decision"`
	Reason             string         `json:"reason,omitempty"`
	RowCap             int            `json:"row_cap,omitempty"`
	Rows               int            `json:"rows"`
	CommandTag         string         `json:"command_tag,omitempty"`
	Status             string         `json:"status"`
	ErrorCode          string         `json:"error_code,omitempty"`
	ErrorMessage       string         `json:"error_message,omitempty"`
	ParameterCount     int            `json:"parameter_count,omitempty"`
	ParametersRedacted bool           `json:"parameters_redacted"`
	StartedAt          time.Time      `json:"started_at"`
	Duration           time.Duration  `json:"duration"`
}

type noopRecorder struct{}

func (noopRecorder) BeginSession(context.Context, *Session) error      { return nil }
func (noopRecorder) RecordQuery(context.Context, QueryRecord) error    { return nil }
func (noopRecorder) EndSession(context.Context, *Session, error) error { return nil }
