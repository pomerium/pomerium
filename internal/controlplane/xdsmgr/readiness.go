package xdsmgr

import (
	"fmt"
	"slices"
	"strings"
)

var requiredTypeURLs = []string{clusterTypeURL, listenerTypeURL, routeConfigurationTypeURL}

type typeSync struct {
	synced bool
	nack   string
}

// syncState is used to keep track which resources we successfully initially synced
// at the start of the stream. Our required envoy objects like Clusters,Listeners & Routes
// need to be synced at least once for Pomerium to be at least considered `Ready` to
// serve inbound traffic.
// Currently, this does not include user-defined routes and policy readiness at Startup,
// due to how we structure OnConfigChange and XDS resource construction.
type syncState struct {
	active bool
	endErr error
	types  map[string]*typeSync
}

func newSyncState() *syncState {
	s := &syncState{types: map[string]*typeSync{}}
	for _, typeURL := range requiredTypeURLs {
		s.types[typeURL] = &typeSync{}
	}
	return s
}

func (s *syncState) endLocked(err error) {
	s.active = false
	s.endErr = err
}

func (s *syncState) inactiveReasonLocked() string {
	if s.endErr != nil {
		return "stream ended: " + s.endErr.Error()
	}
	return "no active stream"
}

func (s *syncState) sentLocked(typeURL string) {
	if _, ok := s.types[typeURL]; !ok {
		s.types[typeURL] = &typeSync{}
	}
}

func (s *syncState) ackLocked(typeURL string) {
	if t, ok := s.types[typeURL]; ok {
		t.synced = true
		t.nack = ""
	}
}

func (s *syncState) nackLocked(typeURL, message string) {
	if t, ok := s.types[typeURL]; ok {
		t.nack = message
	}
}

func (s *syncState) readyLocked() bool {
	for _, t := range s.types {
		if !t.synced {
			return false
		}
	}
	return true
}

func (s *syncState) reasonLocked() string {
	var waiting, parts []string
	for _, typeURL := range s.sortedTypeURLs() {
		t := s.types[typeURL]
		switch {
		case t.synced:
		case t.nack != "":
			parts = append(parts, fmt.Sprintf("%s NACK: %s", typeName(typeURL), t.nack))
		default:
			waiting = append(waiting, typeName(typeURL))
		}
	}
	if len(waiting) > 0 {
		parts = append([]string{"waiting for ACK: " + strings.Join(waiting, ", ")}, parts...)
	}
	return strings.Join(parts, "; ")
}

func (s *syncState) detailsLocked() map[string]string {
	details := make(map[string]string, len(s.types))
	for typeURL, t := range s.types {
		name := typeName(typeURL)
		if !t.synced {
			details[name] = "pending"
			continue
		}
		details[name] = "synced"
		if t.nack != "" {
			details[name+".nack"] = t.nack
		}
	}
	return details
}

func (s *syncState) sortedTypeURLs() []string {
	typeURLs := slices.Clone(requiredTypeURLs)
	var others []string
	for typeURL := range s.types {
		if !slices.Contains(requiredTypeURLs, typeURL) {
			others = append(others, typeURL)
		}
	}
	slices.Sort(others)
	return append(typeURLs, others...)
}
