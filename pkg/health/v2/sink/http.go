package sink

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

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

func (h *HTTP) Run() {}

func (h *HTTP) Shutdown(context.Context) {}

type httpCondition struct {
	OK      bool              `json:"ok"`
	Reason  string            `json:"reason,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

type httpEntry struct {
	Status      string        `json:"status"`
	Initialized httpCondition `json:"initialized"`
	Ready       httpCondition `json:"ready"`
	Healthy     httpCondition `json:"healthy"`
}

type httpStatusPayload struct {
	Statuses map[string]httpEntry `json:"statuses"`
	Checks   []string             `json:"checks"`
}

type httpProbe struct {
	name string
	cond func(healthv2.CheckerStatus) healthv2.Condition
	pass func(healthv2.Snapshot) bool
}

var (
	startupProbe = httpProbe{
		name: "initialized",
		cond: func(c healthv2.CheckerStatus) healthv2.Condition { return c.Initialized },
		pass: healthv2.Snapshot.Initialized,
	}
	readyProbe = httpProbe{
		name: "ready",
		cond: func(c healthv2.CheckerStatus) healthv2.Condition { return c.Ready },
		pass: healthv2.Snapshot.Ready,
	}
	livenessProbe = httpProbe{
		name: "healthy",
		cond: func(c healthv2.CheckerStatus) healthv2.Condition { return c.Healthy },
		pass: healthv2.Snapshot.Healthy,
	}
)

func (h *HTTP) StartupProbe(w http.ResponseWriter, r *http.Request) {
	h.probe(w, r, startupProbe)
}

func (h *HTTP) ReadyProbe(w http.ResponseWriter, r *http.Request) {
	h.probe(w, r, readyProbe)
}

func (h *HTTP) LivenessProbe(w http.ResponseWriter, r *http.Request) {
	h.probe(w, r, livenessProbe)
}

func (h *HTTP) Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	snap := *h.latest.Load()
	payload, err := json.MarshalIndent(httpStatusPayload{
		Statuses: httpEntries(snap),
		Checks:   snap.Keys(),
	}, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (h *HTTP) probe(w http.ResponseWriter, r *http.Request, p httpProbe) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	snap := *h.latest.Load()
	payload, _ := json.MarshalIndent(p.entries(snap), "", "  ")

	w.Header().Set("Content-Type", "application/json")
	if p.pass(snap) {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	if r.Method == http.MethodGet {
		_, _ = w.Write(payload)
	}
}

func (p httpProbe) entries(snap healthv2.Snapshot) map[string]map[string]any {
	entries := map[string]map[string]any{}
	for _, c := range snap.Checkers {
		cond := newHTTPCondition(p.cond(c))
		entry := map[string]any{p.name: cond.OK}
		if cond.Reason != "" {
			entry["reason"] = cond.Reason
		}
		if len(cond.Details) > 0 {
			entry["details"] = cond.Details
		}
		entries[c.Key()] = entry
	}
	return entries
}

func httpEntries(snap healthv2.Snapshot) map[string]httpEntry {
	entries := map[string]httpEntry{}
	for _, c := range snap.Checkers {
		entries[c.Key()] = httpEntry{
			Status:      c.State().String(),
			Initialized: newHTTPCondition(c.Initialized),
			Ready:       newHTTPCondition(c.Ready),
			Healthy:     newHTTPCondition(c.Healthy),
		}
	}
	return entries
}

func newHTTPCondition(c healthv2.Condition) httpCondition {
	cond := httpCondition{OK: c.OK, Details: c.Info.Details}
	if !c.OK {
		cond.Reason = c.Info.Reason
	}
	return cond
}
