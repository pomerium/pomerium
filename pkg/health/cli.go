package health

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	stdslices "slices"
	"strings"
	"sync"
	"time"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/cenkalti/backoff/v4"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
	healthpb "github.com/pomerium/pomerium/pkg/grpc/health"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/slices"
)

var ErrUnhealthy = errors.New("status unhealthy")

func getHTTPStatus(
	client *http.Client,
	req *http.Request,
	// expectedChecks []Check,
	filter Filter,
) (string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("got unexpected status code %d : %w", resp.StatusCode, ErrUnhealthy)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	msg := &httpStatusPayload{}

	if err := json.Unmarshal(data, msg); err != nil {
		return "", err
	}

	errs := []error{}
	requiredChecks := map[Check]struct{}{}
	for _, check := range msg.Required {
		requiredChecks[check] = struct{}{}
	}

	for check, status := range msg.Statuses {
		delete(requiredChecks, Check(check))
		if stdslices.Contains(filter.Exclude, Check(check)) {
			continue
		}
		if status.Err != "" {
			errs = append(errs, err)
			continue
		}
		if status.Status != StatusRunning.String() {
			errs = append(errs, fmt.Errorf("unhealthy status : %s", status.Status))
		}
	}

	for check := range requiredChecks {
		errs = append(errs, fmt.Errorf("check '%s' required, but not reported on", check))
	}

	if len(errs) > 0 {
		errs = append(errs, ErrUnhealthy)
	}

	return string(data), errors.Join(errs...)
}

func BuildHealthCommand() *cobra.Command {
	var addr string
	var excludeFilters []string
	var verbose bool
	cmd := &cobra.Command{
		Use: "health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client := http.DefaultClient

			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, fmt.Sprintf("http://%s/status", addr), nil)
			if err != nil {
				return err
			}

			raw, err := getHTTPStatus(client, req, Filter{Exclude: slices.Map(excludeFilters, func(e string) Check {
				return Check(e)
			})})
			if verbose && raw != "" {
				cmd.Println(raw)
			}
			return err
		},
	}
	cmd.AddCommand(BuildHealthWatchCommand())

	cmd.Flags().StringVarP(
		&addr,
		"health-addr",
		"a",
		"127.0.0.1:28080",
		"port of the pomerium health check service",
	)

	cmd.Flags().StringArrayVarP(
		&excludeFilters,
		"exclude",
		"e",
		[]string{},
		"list of health checks to exclude from consideration",
	)
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "prints extra health information")
	return cmd
}

func getStreamByGrpcAddr(ctx context.Context, grpcAddr, sharedSecret string) (healthpb.HealthNotifierClient, error) {
	signedKey, err := base64.StdEncoding.DecodeString(sharedSecret)
	if err != nil {
		return nil, err
	}
	dialOpts := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(grpcutil.WithUnarySignedJWT(func() []byte { return signedKey })),
		grpc.WithChainStreamInterceptor(grpcutil.WithStreamSignedJWT(func() []byte { return signedKey })),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	log.Ctx(ctx).Info().Msg("acquiring grpc client")
	cc, err := grpc.NewClient(grpcAddr, dialOpts...)
	if err != nil {
		return nil, err
	}

	return healthpb.NewHealthNotifierClient(cc), nil
}

func BuildHealthWatchCommand() *cobra.Command {
	var grpcAddr string
	var sharedSecret string
	cmd := &cobra.Command{
		Use:     "watch",
		Aliases: []string{"w"},
		Short:   "watch the grpc health stream for health updates",
		Long:    "this must be run locally against the allocated grpc port for pomerium",
		RunE: func(cmd *cobra.Command, _ []string) error {
			streamCtx, ca := context.WithCancel(cmd.Context())
			defer ca()
			healthSvc, err := getStreamByGrpcAddr(streamCtx, grpcAddr, sharedSecret)
			if err != nil {
				log.Ctx(streamCtx).Err(err).Msg("failed to acquire health notifier client")
				return err
			}
			log.Ctx(streamCtx).Info().Msg("acquiried health notifier client")

			cl, err := healthSvc.SyncHealth(streamCtx, &healthpb.HealthStreamRequest{})
			if err != nil {
				log.Ctx(streamCtx).Err(err).Msg("failed to stream health")
				return err
			}

			initialMsg, err := backoff.RetryWithData(func() (*healthpb.HealthMessage, error) {
				initialMsg, err := cl.Recv()
				if errors.Is(err, io.EOF) {
					return nil, backoff.Permanent(err)
				}
				if err != nil {
					st, ok := status.FromError(err)
					if !ok {
						log.Ctx(streamCtx).Err(err).Msg("failed to get initial message")
						return nil, err
					}
					if st.Code() == codes.DeadlineExceeded ||
						st.Code() == codes.FailedPrecondition ||
						st.Code() == codes.Canceled {
						return nil, backoff.Permanent(err)
					}
					log.Ctx(streamCtx).Err(err).Msg("failed to get initial message")
					return nil, err
				}
				return initialMsg, nil
			}, backoff.WithContext(backoff.NewExponentialBackOff(), streamCtx))
			if err != nil {
				return fmt.Errorf("failed to receive an intiail message from the health stream : %w", err)
			}
			w, h, _ := term.GetSize(int(os.Stdout.Fd()))
			model := newHealthTUI(initialMsg, w, h)
			eg, ctx := errgroup.WithContext(streamCtx)
			eg.Go(func() error {
				for {
				RETRY:
					select {
					case <-ctx.Done():
						return ctx.Err()
					default:
						msg, err := cl.Recv()
						if errors.Is(err, io.EOF) {
							return fmt.Errorf("remote stream closed")
						} else if err != nil {
							st, ok := status.FromError(err)
							if !ok {
								goto RETRY
							}
							if st.Code() == codes.FailedPrecondition ||
								st.Code() == codes.DeadlineExceeded {
								return fmt.Errorf("server closed the health stream")
							}
							if st.Code() == codes.Canceled {
								return err
							}
						}
						model.SetState(msg)
					}
				}
			})

			eg.Go(func() error {
				// cancels the parent stream context.
				defer ca()
				if _, err := tea.NewProgram(
					model,
					tea.WithContext(ctx),
					tea.WithWindowSize(w, h),
				).Run(); err != nil {
					return err
				}
				return nil
			})
			waitErr := eg.Wait()
			cmd.Print("\033[H\033[2J")

			// errors.Is() with context.Cancelled doesn't catch client side streaming cancellation
			if waitErr != nil && strings.Contains(waitErr.Error(), "context canceled") {
				return nil
			}
			return waitErr
		},
	}
	cmd.Flags().StringVarP(&grpcAddr, "grpc-addr", "a", "", "external grpc address")
	cmd.Flags().StringVarP(&sharedSecret, "shared-secret", "s", "", "base64 encoded pomerium shared secret")
	return cmd
}

type model struct {
	table          table.Model
	stateMu        sync.Mutex
	state          *healthpb.HealthMessage
	detailsWrapped string
	width          int
	height         int
}

func (m *model) SetState(msg *healthpb.HealthMessage) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.state = msg
}

type tickMsg struct{}

func (m *model) Init() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg {
		return tickMsg{}
	})
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			if m.table.Focused() {
				m.table.Blur()
			} else {
				m.table.Focus()
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			row := m.table.SelectedRow()
			check := row[0]
			err := row[2]
			var details string
			if err == "" {
				details = fmt.Sprintf("%s : healthy", check)
			} else {
				details = fmt.Sprintf("%s : %s", check, err)
			}
			var lineCount int
			m.detailsWrapped, lineCount = wrapText(details, m.width)
			m.table.SetHeight(m.height - 2 - lineCount)
		}
	case tea.WindowSizeMsg:
		w, h := msg.Width, msg.Height
		m.width = w
		m.height = h
		m.table.SetWidth(w)
		var lineCount int
		m.detailsWrapped, lineCount = wrapText(m.detailsWrapped, w)
		m.table.SetHeight(h - 2 - lineCount)
		return m, nil
	case tickMsg:
		m.stateMu.Lock()
		rows := toTableRows(m.state)
		m.stateMu.Unlock()
		m.table.SetRows(rows)
		return m, tea.Tick(time.Second, func(time.Time) tea.Msg {
			return tickMsg{}
		})
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m *model) View() tea.View {
	return tea.NewView(m.table.View() + "\n" + m.detailsWrapped + "\n" + m.table.HelpView())
}

func newHealthTUI(initialState *healthpb.HealthMessage, w, h int) *model {
	wP := w - 2
	columns := []table.Column{
		{Title: "Check", Width: wP / 3},
		{Title: "Status", Width: wP / 3},
		{Title: "Error", Width: wP / 3},
	}

	tbl := table.New(
		table.WithHeight(h-2),
		table.WithWidth(w),
		table.WithColumns(columns),
		table.WithRows(toTableRows(initialState)),
		table.WithFocused(true),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Background(lipgloss.Color("8")).
		Bold(true)
	tbl.SetStyles(s)
	tbl.Focus()
	tbl.SetCursor(0)

	m := &model{table: tbl, state: initialState, width: w, height: h}

	return m
}

func toTableRows(msg *healthpb.HealthMessage) []table.Row {
	rows := []table.Row{}

	type pair struct {
		check           string
		componentStatus *healthpb.ComponentStatus
	}
	all := []pair{}
	for st, details := range msg.GetStatuses() {
		all = append(all, pair{
			check:           st,
			componentStatus: details,
		})
	}

	stdslices.SortFunc(all, func(a, b pair) int {
		errA := a.componentStatus.GetErr()
		errB := b.componentStatus.GetErr()

		// xor
		if (len(errA) > 0) != (len(errB) > 0) {
			if len(errB) > 0 {
				return 1
			}
			return -1
		}

		if a.componentStatus.Status != b.componentStatus.Status {
			return int(b.componentStatus.GetStatus() - a.componentStatus.GetStatus())
		}

		return strings.Compare(a.check, b.check)
	})

	for _, val := range all {
		check := val.check
		st := ""
		switch val.componentStatus.GetStatus() {
		case healthpb.HealthStatus_HEALTH_STATUS_UNKNOWN:
			st = warnStyle.Render("STARTING")
		case healthpb.HealthStatus_HEALTH_STATUS_RUNNING:
			st = okStyle.Render("RUNNING")
		case healthpb.HealthStatus_HEALTH_STATUS_TERMINATING:
			st = terminatingStyle.Render("TERMINATING")
		}
		if val.componentStatus.GetErr() != "" {
			check = errStyle.Render(check)
		} else {
			check = okStyle.Render(check)
		}
		rows = append(
			rows,
			table.Row{
				check,
				st,
				val.componentStatus.GetErr(),
			},
		)
	}
	return rows
}

func wrapText(text string, width int) (string, int) {
	if width <= 0 || len(text) <= width {
		return text, 1
	}

	var result strings.Builder
	words := strings.Fields(text)
	if len(words) == 0 {
		return text, 1
	}

	lineCount := 1
	lineLen := 0
	for i, word := range words {
		wordLen := len(word)
		if i == 0 {
			result.WriteString(word)
			lineLen += wordLen
			continue
		}

		if lineLen+1+wordLen > width {
			result.WriteString("\n")
			result.WriteString(word)
			lineLen = wordLen
			lineCount++
		} else {
			result.WriteString(" ")
			result.WriteString(word)
			lineLen += 1 + wordLen
		}
	}
	return result.String(), lineCount
}

var (
	okStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))   // green
	warnStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("214")) // yellow
	errStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("196")) // red
	terminatingStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244")) // grey
)
