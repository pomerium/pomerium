package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	stdslices "slices"

	"github.com/spf13/cobra"

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

	if len(requiredChecks) > 0 || len(errs) > 0 {
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
