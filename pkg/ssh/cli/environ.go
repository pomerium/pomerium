package cli

import (
	"fmt"

	"github.com/muesli/termenv"
	"github.com/pomerium/pomerium/pkg/ssh/api"
)

type sshEnviron struct {
	Env map[string]string
}

// Environ implements termenv.Environ.
func (s *sshEnviron) Environ() []string {
	kv := make([]string, 0, len(s.Env))
	for k, v := range s.Env {
		kv = append(kv, fmt.Sprintf("%s=%s", k, v))
	}
	return kv
}

// Getenv implements termenv.Environ.
func (s *sshEnviron) Getenv(key string) string {
	return s.Env[key]
}

var _ termenv.Environ = (*sshEnviron)(nil)

func NewSSHEnviron(ptyInfo api.SSHPtyInfo) termenv.Environ {
	return &sshEnviron{
		Env: map[string]string{
			"TERM":      ptyInfo.GetTermEnv(),
			"TTY_FORCE": "1",
		},
	}
}
