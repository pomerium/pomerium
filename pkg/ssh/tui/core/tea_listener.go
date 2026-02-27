package core

import (
	"slices"

	tea "charm.land/bubbletea/v2"
	"google.golang.org/protobuf/proto"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/models"
)

type TeaMsgSender interface {
	SendTeaMsg(msg tea.Msg)
}

type TeaListener[T models.Item[K], K comparable] struct {
	sender TeaMsgSender
}

func NewTeaListener[T models.Item[K], K comparable](sender TeaMsgSender) *TeaListener[T, K] {
	return &TeaListener[T, K]{
		sender: sender,
	}
}

func (tl *TeaListener[T, K]) OnIndexUpdate(begin models.Index, end models.Index, items []T) {
	tl.sender.SendTeaMsg(models.IndexUpdateMsg[T, K]{
		Begin: begin,
		End:   end,
		Items: slices.Clone(items),
	})
}

func (tl *TeaListener[T, K]) OnModelReset(items []T) {
	tl.sender.SendTeaMsg(models.ModelResetMsg[T, K]{
		Items: slices.Clone(items),
	})
}

func (tl *TeaListener[T, K]) OnDiagnosticsReceived(diagnostics []*extensions_ssh.Diagnostic) {
	for _, d := range diagnostics {
		tl.sender.SendTeaMsg(proto.CloneOf(d))
	}
}
