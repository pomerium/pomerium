package health

import (
	"encoding/json"
	"net/http"
)

type HttpProvider struct {
	expectedStatusesFn func() map[Check]struct{}
	reportedStatuses   *Deduplicator
}

type HttpProviderOptions struct {
	expectedStatusesFn func() map[Check]struct{}
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

func NewHttpProvider(options ...HttpProviderOption) *HttpProvider {
	defaultOpts := &HttpProviderOptions{}
	defaultOpts.Apply(options...)
	if defaultOpts.expectedStatusesFn == nil {
		defaultOpts.expectedStatusesFn = getDefaultExpected
	}

	return &HttpProvider{
		expectedStatusesFn: defaultOpts.expectedStatusesFn,
		reportedStatuses:   NewDeduplicator(),
	}
}

var _ Provider = (*HttpProvider)(nil)

func (h *HttpProvider) ReportOK(check Check, attrs ...Attr) {
	h.reportedStatuses.ReportOK(check, attrs...)
}

func (h *HttpProvider) ReportStatus(check Check, status Status, attrs ...Attr) {
	h.reportedStatuses.ReportStatus(check, status, attrs...)
}

func (h *HttpProvider) ReportError(check Check, err error, attrs ...Attr) {
	h.reportedStatuses.ReportError(check, err, attrs...)
}

type httpRecord struct {
	Err        string `json:"error,omitempty"`
	Attributes []Attr `json:"attributes,omitempty"`
}

func (h *HttpProvider) ReadinessProbe(w http.ResponseWriter, r *http.Request) {
	expected := h.expectedStatusesFn()
	records := h.reportedStatuses.GetRecords()
	seenAll := true
	succeeded := true
	resp := map[string]httpRecord{}
	// resp := strings.Builder{}
	for status := range expected {
		details, ok := records[status]
		if !ok {
			seenAll = false
			resp[string(status)] = httpRecord{
				Err: "status not reported, but expected",
			}
			continue
		}
		if details.err != nil {
			succeeded = false
			resp[string(status)] = httpRecord{
				Err:        details.err.Error(),
				Attributes: details.Attr(),
			}
			continue
		}

		resp[string(status)] = httpRecord{
			Attributes: details.Attr(),
		}
	}

	respData, _ := json.MarshalIndent(resp, "", "  ")
	if !seenAll || !succeeded {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write(respData)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(respData)
}

func (h *HttpProvider) StartupProbe(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *HttpProvider) LivelinessProbe(w http.ResponseWriter, r *http.Request) {
	expected := h.expectedStatusesFn()
	records := h.reportedStatuses.GetRecords()
	seenAll := true
	succeeded := true
	resp := map[string]httpRecord{}
	// resp := strings.Builder{}
	for status := range expected {
		details, ok := records[status]
		if !ok {
			seenAll = false
			resp[string(status)] = httpRecord{
				Err: "status not reported, but expected",
			}
			continue
		}
		if details.err != nil {
			succeeded = false
			resp[string(status)] = httpRecord{
				Err:        details.err.Error(),
				Attributes: details.Attr(),
			}
			continue
		}

		resp[string(status)] = httpRecord{
			Attributes: details.Attr(),
		}
	}

	respData, _ := json.MarshalIndent(resp, "", "  ")
	if !seenAll || !succeeded {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write(respData)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(respData)
}
