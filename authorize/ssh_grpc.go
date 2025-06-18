package authorize

import (
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (a *Authorize) ManageStream(extensions_ssh.StreamManagement_ManageStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method ManageStream not implemented")
}

func (a *Authorize) ServeChannel(extensions_ssh.StreamManagement_ServeChannelServer) error {
	return status.Errorf(codes.Unimplemented, "method ServeChannel not implemented")
}
