package health

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/samber/lo"
)

type HttpProvider struct {
	expectedStatusesFn func() map[Check]struct{}
	startupFilter      Filter
	readyFilter        Filter
	liveFilter         Filter
	tracker            Tracker
}

type HttpProviderOptions struct {
	expectedStatusesFn func() map[Check]struct{}
	startupFilter      *Filter
	readyFilter        *Filter
	liveFilter         *Filter
	tracker            Tracker
}

func (o *HttpProviderOptions) Apply(opts ...HttpProviderOption) {
	for _, opt := range opts {
		opt(o)
	}
}

type HttpProviderOption func(o *HttpProviderOptions)

func WithExpectedStatusesFn(fn func() map[Check]struct{}) HttpProviderOption {
	return func(o *HttpProviderOptions) {
		o.expectedStatusesFn = fn
	}
}

func WithHealthTracker(tr Tracker) HttpProviderOption {
	return func(o *HttpProviderOptions) {
		o.tracker = tr
	}
}

func WithStartupFilter(filter Filter) HttpProviderOption {
	return func(o *HttpProviderOptions) {
		o.startupFilter = &filter
	}
}

func WithReadyFilter(filter Filter) HttpProviderOption {
	return func(o *HttpProviderOptions) {
		o.readyFilter = &filter
	}
}

func WithLivelinessFilter(filter Filter) HttpProviderOption {
	return func(o *HttpProviderOptions) {
		o.liveFilter = &filter
	}
}

func NewHttpProvider(options ...HttpProviderOption) *HttpProvider {
	defaultOpts := &HttpProviderOptions{}
	defaultOpts.Apply(options...)
	if defaultOpts.expectedStatusesFn == nil {
		defaultOpts.expectedStatusesFn = getDefaultExpected
	}
	if defaultOpts.readyFilter == nil {
		defaultOpts.readyFilter = &Filter{
			Exclude: []Check{},
		}
	}
	if defaultOpts.startupFilter == nil {
		defaultOpts.startupFilter = &Filter{
			Exclude: []Check{},
		}
	}
	if defaultOpts.liveFilter == nil {
		defaultOpts.liveFilter = &Filter{
			Exclude: []Check{},
		}
	}

	return &HttpProvider{
		expectedStatusesFn: defaultOpts.expectedStatusesFn,
		readyFilter:        *defaultOpts.readyFilter,
		startupFilter:      *defaultOpts.startupFilter,
		liveFilter:         *defaultOpts.liveFilter,
		tracker:            defaultOpts.tracker,
	}
}

var _ Provider = (*HttpProvider)(nil)

// no-op
func (h *HttpProvider) ReportOK(check Check, attrs ...Attr) {}

// no-op
func (h *HttpProvider) ReportStatus(check Check, status Status, attrs ...Attr) {}

// no-op
func (h *HttpProvider) ReportError(check Check, err error, attrs ...Attr) {}

type httpHealtyEntry struct {
	Status     string `json:"status"`
	Err        string `json:"error,omitempty"`
	Attributes []Attr `json:"attributes,omitempty"`
}

type healthCmp func(Check, *record) (httpHealtyEntry, bool)

func cmpStartupHealth(c Check, r *record) (httpHealtyEntry, bool) {
	if r == nil {
		return httpHealtyEntry{
			Status: "UNAIVALABLE",
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
	return entry, r.status != StatusStarting
}

func cmpReadyHealth(c Check, r *record) (httpHealtyEntry, bool) {
	if r == nil {
		return httpHealtyEntry{
			Status: "UNAIVALABLE",
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

func cmpLivelinessHealth(c Check, r *record) (httpHealtyEntry, bool) {
	if r == nil {
		return httpHealtyEntry{
			Status: "UNAIVALABLE",
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
	// when Kubernetes starts gracefull terminating a pod, we should treat the reported
	// StatusTerminating as still being healthy, unless it is in an error state
	return entry, r.status != StatusStarting && r.err == nil
}

func (h *HttpProvider) collectStatusRecords(
	filter Filter,
	cmp healthCmp,
) (payload []byte, healthy bool) {
	expected := h.expectedStatusesFn()
	toCheck, _ := lo.Difference(lo.Keys(expected), filter.Exclude)
	records := h.tracker.GetRecords()
	healthy = true

	resp := map[string]httpHealtyEntry{}
	for _, status := range toCheck {
		details := records[status]
		entry, reportedHealthy := cmp(status, details)
		resp[string(status)] = entry
		if !reportedHealthy {
			slog.Default().With("check", status, "err", entry.Err, "status", entry.Status).Info("reported unhealthy in http probe")
			healthy = false
		}
	}

	respData, _ := json.MarshalIndent(resp, "", "  ")
	return respData, healthy
}

func (h *HttpProvider) ReadinessProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	payload, healthy := h.collectStatusRecords(
		h.readyFilter,
		cmpReadyHealth,
	)
	if healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		w.Write(payload)
	}
}

func (h *HttpProvider) StartupProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	payload, healthy := h.collectStatusRecords(
		h.startupFilter,
		cmpStartupHealth,
	)
	if healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		w.Write(payload)
	}
}

func (h *HttpProvider) LivelinessProbe(w http.ResponseWriter, r *http.Request) {
	payload, healthy := h.collectStatusRecords(
		h.liveFilter,
		cmpLivelinessHealth,
	)
	if healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		w.Write(payload)
	}
}
