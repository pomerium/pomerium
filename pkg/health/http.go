package health

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	stdslices "slices"

	"github.com/pomerium/pomerium/pkg/slices"
)

type HTTPProvider struct {
	expectedStatusesFn func() map[Check]struct{}
	tracker            Tracker

	// Filters are currently a no-op,
	// we could decide to have these be configuration driven
	globalFilter Filter
}

func NewHTTPProvider(tr Tracker, options ...CheckOption) *HTTPProvider {
	defaultOpts := &CheckOptions{}
	defaultOpts.Apply(options...)

	return &HTTPProvider{
		expectedStatusesFn: func() map[Check]struct{} {
			return defaultOpts.expected
		},
		globalFilter: Filter{
			Exclude: []Check{
				ZeroBootstrapConfigSave,
				ZeroConnect,
				ZeroRoutesReachable,
			},
		},
		tracker: tr,
	}
}

var _ Provider = (*HTTPProvider)(nil)

// no-op
func (h *HTTPProvider) ReportOK(_ Check, _ ...Attr) {}

// no-op
func (h *HTTPProvider) ReportStatus(_ Check, _ Status, _ ...Attr) {}

// no-op
func (h *HTTPProvider) ReportError(_ Check, _ error, _ ...Attr) {}

type httpHealtyEntry struct {
	Status     string `json:"status"`
	Err        string `json:"error,omitempty"`
	Attributes []Attr `json:"attributes,omitempty"`
}

type healthCmp func(Check, *Record) (httpHealtyEntry, bool)

func cmpStartupHealth(c Check, r *Record) (httpHealtyEntry, bool) {
	if r == nil {
		return httpHealtyEntry{
			Status: "UNAVAILABLE",
			Err:    fmt.Sprintf("expected ':%s' to have been reported on, but was not", c),
		}, false
	}

	entry := httpHealtyEntry{
		Status:     r.status.String(),
		Attributes: r.Attr(),
	}

	if r.err != nil {
		entry.Err = r.err.Error()
	}

	// here we intentionally do not treat errors as unsuccessful,
	// as long as the reported state has moved out of starting
	return entry, r.status != StatusUnknown
}

func cmpReadyHealth(c Check, r *Record) (httpHealtyEntry, bool) {
	if r == nil {
		return httpHealtyEntry{
			Status: "UNAVAILABLE",
			Err:    fmt.Sprintf("expected ':%s' to have been reported on, but was not", c),
		}, false
	}

	entry := httpHealtyEntry{
		Status:     r.status.String(),
		Attributes: r.Attr(),
	}

	if r.err != nil {
		entry.Err = r.err.Error()
	}
	// terminating should stop accepting connections even if all replicas in the deployment are
	// in the terminating state
	return entry, r.status == StatusRunning && r.err == nil
}

func cmpLivelinessHealth(c Check, r *Record) (httpHealtyEntry, bool) {
	if r == nil {
		return httpHealtyEntry{
			Status: "UNAVAILABLE",
			Err:    fmt.Sprintf("expected ':%s' to have been reported on, but was not", c),
		}, false
	}

	entry := httpHealtyEntry{
		Status:     r.status.String(),
		Attributes: r.Attr(),
	}

	if r.err != nil {
		entry.Err = r.err.Error()
	}
	// here we intentionally do not treat StatusTerminating as unhealthy
	// when Kubernetes starts graceful terminating a pod, we should treat the reported
	// StatusTerminating as still being healthy, unless it is in an error state
	return entry, r.status != StatusUnknown && r.err == nil
}

func (h *HTTPProvider) collectStatusRecords(
	filter Filter,
	cmp healthCmp,
) (payload []byte, healthy bool) {
	expected := h.expectedStatusesFn()
	toCheck, _ := slices.Difference(stdslices.Collect(maps.Keys(expected)), filter.Exclude)
	records := h.tracker.GetRecords()
	healthy = true

	resp := map[string]httpHealtyEntry{}
	for _, status := range toCheck {
		details := records[status]
		entry, reportedHealthy := cmp(status, details)
		resp[string(status)] = entry
		if !reportedHealthy {
			healthy = false
		}
	}

	respData, _ := json.MarshalIndent(resp, "", "  ")
	return respData, healthy
}

func (h *HTTPProvider) StartupProbe(w http.ResponseWriter, r *http.Request) {
	h.probe(cmpStartupHealth).ServeHTTP(w, r)
}

func (h *HTTPProvider) ReadyProbe(w http.ResponseWriter, r *http.Request) {
	h.probe(cmpReadyHealth).ServeHTTP(w, r)
}

func (h *HTTPProvider) LivenessProbe(w http.ResponseWriter, r *http.Request) {
	h.probe(cmpLivelinessHealth).ServeHTTP(w, r)
}

func (h *HTTPProvider) probe(healthcmp healthCmp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		payload, healthy := h.collectStatusRecords(
			h.globalFilter,
			healthcmp,
		)
		if healthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write(payload)
		}
	}
}
