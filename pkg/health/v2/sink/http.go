package sink

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

const statusUnavailable = "UNAVAILABLE"

type HTTP struct {
	latest atomic.Pointer[healthv2.Snapshot]
}

var _ healthv2.HealthSink = (*HTTP)(nil)

func NewHTTP() *HTTP {
	h := &HTTP{}
	h.latest.Store(&healthv2.Snapshot{})
	return h
}

func (h *HTTP) Notify(snap healthv2.Snapshot) { h.latest.Store(&snap) }

func (h *HTTP) Close() {}

type httpEntry struct {
	Status     string       `json:"status"`
	Err        string       `json:"error,omitempty"`
	Attributes []check.Attr `json:"attributes,omitempty"`
	Group      string       `json:"group,omitempty"`
}

type httpStatusPayload struct {
	Statuses map[string]httpEntry `json:"statuses"`
	Required []string             `json:"checks"`
}

func (h *HTTP) StartupProbe(w http.ResponseWriter, r *http.Request) {
	h.probe(w, r, healthv2.Snapshot.Started)
}

func (h *HTTP) ReadyProbe(w http.ResponseWriter, r *http.Request) {
	h.probe(w, r, healthv2.Snapshot.Ready)
}

func (h *HTTP) LivenessProbe(w http.ResponseWriter, r *http.Request) {
	h.probe(w, r, healthv2.Snapshot.Live)
}

func (h *HTTP) Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	snap := *h.latest.Load()

	statuses := map[string]httpEntry{}
	for _, c := range snap.Checkers {
		for _, res := range c.Results {
			if !res.Reported() {
				continue
			}
			entry := resultEntry(res)
			entry.Group = string(c.Group)
			statuses[string(res.Name)] = entry
		}
	}
	payload, err := json.MarshalIndent(httpStatusPayload{
		Statuses: statuses,
		Required: snap.Required(),
	}, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (h *HTTP) probe(w http.ResponseWriter, r *http.Request, healthy func(healthv2.Snapshot) bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	snap := *h.latest.Load()
	payload, _ := json.MarshalIndent(probeEntries(snap), "", "  ")

	w.Header().Set("Content-Type", "application/json")
	if healthy(snap) {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	if r.Method == http.MethodGet {
		_, _ = w.Write(payload)
	}
}

func probeEntries(snap healthv2.Snapshot) map[string]httpEntry {
	entries := map[string]httpEntry{}
	for _, c := range snap.Checkers {
		for _, res := range c.Results {
			entries[string(res.Name)] = probeEntry(res)
		}
	}
	return entries
}

func probeEntry(res check.Result) httpEntry {
	if !res.Reported() {
		return httpEntry{
			Status: statusUnavailable,
			Err:    fmt.Sprintf("expected ':%s' to have been reported on, but was not", res.Name),
		}
	}
	return resultEntry(res)
}

func resultEntry(res check.Result) httpEntry {
	entry := httpEntry{
		Status:     res.Status.String(),
		Attributes: res.Attrs,
	}
	if res.Err != nil {
		entry.Err = res.Err.Error()
	}
	return entry
}
