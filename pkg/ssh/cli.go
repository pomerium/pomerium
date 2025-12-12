package ssh

import (
	"errors"
	"fmt"
	"io"

	tea "charm.land/bubbletea/v2"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"

	"github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
)

type InternalCLI interface {
	Stdin() io.Reader
	Stdout() io.Writer
	Stderr() io.Writer
	PtyInfo() *ssh.SSHDownstreamPTYInfo
	SendTeaMsg(msg tea.Msg)
	RunProgram(prog *tea.Program) (tea.Model, error)
}

// ErrHandoff is a sentinel error to indicate that the command triggered a handoff,
// and we should not automatically disconnect
var ErrHandoff = errors.New("handoff")

// ErrDeleteSessionOnExit is a sentinel error to indicate that the authorized
// session should be deleted once the SSH connection ends.
var ErrDeleteSessionOnExit = errors.New("delete_session_on_exit")

type internalCLI struct {
	*cobra.Command
	programDone chan struct{}
	msgQueue    chan tea.Msg
	ptyInfo     *ssh.SSHDownstreamPTYInfo
	username    string
	stdin       io.Reader
	stdout      io.Writer
	stderr      io.Writer
}

func newInternalCLI(
	ctrl ChannelControlInterface,
	ptyInfo *ssh.SSHDownstreamPTYInfo,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) *internalCLI {
	cmd := &cobra.Command{
		Use: "pomerium",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			_, cmdIsInteractive := cmd.Annotations["interactive"]
			switch {
			case (ptyInfo == nil) && cmdIsInteractive:
				return fmt.Errorf("\x1b[31m'%s' is an interactive command and requires a TTY (try passing '-t' to ssh)\x1b[0m", cmd.Use)
			}
			return nil
		},
	}

	cmd.CompletionOptions.DisableDefaultCmd = true
	// set a non-nil args list, otherwise it will read from os.Args by default
	cmd.SetArgs([]string{})
	cmd.SetIn(stdin)
	cmd.SetOut(stderr) // usage messages
	cmd.SetErr(stderr) // error messages
	cmd.SilenceUsage = true

	cli := &internalCLI{
		Command:     cmd,
		programDone: make(chan struct{}),
		msgQueue:    make(chan tea.Msg, 256),
		ptyInfo:     ptyInfo,
		username:    *ctrl.Username(),
		stdin:       stdin,
		stdout:      stdout,
		stderr:      stderr,
	}

	return cli
}

// PtyInfo implements InternalCLI.
func (cli *internalCLI) PtyInfo() *ssh.SSHDownstreamPTYInfo {
	return cli.ptyInfo
}

// Stderr implements InternalCLI.
func (cli *internalCLI) Stderr() io.Writer {
	return cli.stderr
}

// Stdin implements InternalCLI.
func (cli *internalCLI) Stdin() io.Reader {
	return cli.stdin
}

// Stdout implements InternalCLI.
func (cli *internalCLI) Stdout() io.Writer {
	return cli.stdout
}

// SendTeaMsg implements InternalCLI.
func (cli *internalCLI) SendTeaMsg(msg tea.Msg) {
	select {
	case <-cli.programDone:
	case cli.msgQueue <- msg:
	}
}

// SendTeaMsg implements InternalCLI.
func (cli *internalCLI) RunProgram(prog *tea.Program) (tea.Model, error) {
	select {
	case <-cli.programDone:
		return nil, errors.New("RunProgram can only be called once")
	default:
	}
	defer close(cli.programDone)
	go func() {
		for {
			select {
			case <-cli.programDone:
				return
			case msg := <-cli.msgQueue:
				prog.Send(msg)
			}
		}
	}()
	return prog.Run()
}

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

func NewSshEnviron(ptyInfo *ssh.SSHDownstreamPTYInfo) termenv.Environ {
	return &sshEnviron{
		Env: map[string]string{
			"TERM":      ptyInfo.TermEnv,
			"TTY_FORCE": "1",

			// Important: disables synchronized output querying which I think
			// might be causing the renderer to get stuck
			"SSH_TTY": "1",
		},
	}
}
