package ssh

import (
	"errors"
	"fmt"
	"io"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/pomerium/pomerium/pkg/ssh/api"
)

type internalCLI struct {
	*cobra.Command
	programDone chan struct{}
	msgQueue    chan tea.Msg
	ptyInfo     api.SSHPtyInfo
	stdin       io.Reader
	stdout      io.Writer
	stderr      io.Writer
}

func newInternalCLI(
	ptyInfo api.SSHPtyInfo,
	msgQueue chan tea.Msg,
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
	cmd.SilenceErrors = true

	cli := &internalCLI{
		Command:     cmd,
		programDone: make(chan struct{}),
		msgQueue:    msgQueue,
		ptyInfo:     ptyInfo,
		stdin:       stdin,
		stdout:      stdout,
		stderr:      stderr,
	}

	return cli
}

// PtyInfo implements InternalCLI.
func (cli *internalCLI) PtyInfo() api.SSHPtyInfo {
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
