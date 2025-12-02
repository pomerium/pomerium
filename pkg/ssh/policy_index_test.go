package ssh_test

import (
	"context"
	"testing"

	"github.com/pomerium/pomerium/pkg/ssh"
	sshtest "github.com/pomerium/pomerium/pkg/ssh/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestInMemoryPolicyIndexer(t *testing.T) {
	suite.Run(t, sshtest.NewPolicyIndexConformanceSuite(sshtest.TestFuncs[*ssh.InMemoryPolicyIndexer]{
		Create: func(s ssh.SSHEvaluator) *ssh.InMemoryPolicyIndexer {
			return ssh.NewInMemoryPolicyIndexer(s)
		},
		Run: func(ctx context.Context, idx *ssh.InMemoryPolicyIndexer) {
			context.AfterFunc(ctx, idx.Shutdown)
			err := idx.Run(context.WithoutCancel(ctx))
			assert.NoError(t, err)
		},
		NumKnownStreams: func(t *ssh.InMemoryPolicyIndexer) int {
			return len(t.UnexportedState().KnownStreams)
		},
		NumKnownSessions: func(t *ssh.InMemoryPolicyIndexer) int {
			return len(t.UnexportedState().KnownSessions)
		},
	}))
}
