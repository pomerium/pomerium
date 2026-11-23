package envoy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// envoyOverload checks the actual overload actions instead of duplicating their
// resource thresholds. Envoy's admin /ready endpoint remains successful while
// the overload manager stops accepting public connections or requests.
func (srv *Server) envoyOverload(ctx context.Context) error {
	srv.mu.Lock()
	adminAddress := srv.adminAddress
	srv.mu.Unlock()

	u := &url.URL{
		Scheme: "http",
		Host:   "unix",
		Path:   "/stats",
	}
	q := u.Query()
	q.Set("format", "json")
	q.Set("filter", `^overload\.envoy\.overload_actions\.stop_accepting_(connections|requests)\.active$`)
	u.RawQuery = q.Encode()

	client := envoyAdminClient(adminAddress)
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("querying envoy overload actions: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status code from overload stats endpoint: %d", resp.StatusCode)
	}

	var result struct {
		Stats []struct {
			Name  string   `json:"name"`
			Value *float64 `json:"value"`
		} `json:"stats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding envoy overload actions: %w", err)
	}
	if result.Stats == nil {
		return fmt.Errorf("missing envoy overload stats")
	}
	// An empty stats list is valid when no stop-accepting action is configured,
	// for example on platforms without the shared memory resource monitor.
	for _, stat := range result.Stats {
		switch stat.Name {
		case "overload.envoy.overload_actions.stop_accepting_connections.active",
			"overload.envoy.overload_actions.stop_accepting_requests.active":
			if stat.Value == nil {
				return fmt.Errorf("missing envoy overload stat value: %s", stat.Name)
			}
			if *stat.Value > 0 {
				return fmt.Errorf("envoy overloaded: %s is active", stat.Name)
			}
		}
	}
	return nil
}
