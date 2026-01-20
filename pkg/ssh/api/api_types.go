package api //nolint:revive

import (
	"context"
	"iter"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh/models"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

type ChannelControlInterface interface {
	StreamHandlerInterface
	SendControlAction(*extensions_ssh.SSHChannelControlAction) error
	SendMessage(any) error
	RecvMsg() (any, error)
}

type StreamHandlerInterface interface {
	PrepareHandoff(ctx context.Context, hostname string, ptyInfo SSHPtyInfo) (*extensions_ssh.SSHChannelControlAction, error)
	GetSession(ctx context.Context) (*session.Session, error)
	DeleteSession(ctx context.Context) error
	AllSSHRoutes() iter.Seq[*config.Policy]
	Hostname() *string
	Username() *string
	DownstreamChannelID() uint32
	DownstreamSourceAddress() string
	DownstreamPublicKeyFingerprint() []byte
	PortForwardManager() *portforward.Manager

	ChannelDataModel() *models.ChannelModel
	PermissionDataModel() *models.PermissionModel
	RouteDataModel() *models.RouteModel
}

type SSHPtyInfo interface {
	GetTermEnv() string
	GetWidthColumns() uint32
	GetHeightRows() uint32
	GetWidthPx() uint32
	GetHeightPx() uint32
	GetModes() []byte
}
