package check

import "slices"

type Group string

const (
	GroupControlPlane Group = "ControlPlane"
	GroupAuthorize    Group = "Authorize"
	GroupAuthenticate Group = "Authenticate"
	GroupProxy        Group = "Proxy"
	GroupDataBroker   Group = "DataBroker"
	GroupRecording    Group = "Recording"
	GroupIdentity     Group = "Identity"
)

// CheckName is a constant, unique across checkers; per-instance values go in
// Result.Attrs.
type CheckName string

type Status int

const (
	StatusUnknown Status = iota
	StatusRunning
	StatusTerminating
)

func (s Status) String() string {
	switch s {
	case StatusRunning:
		return "RUNNING"
	case StatusTerminating:
		return "TERMINATING"
	default:
		return "UNKNOWN"
	}
}

type Attr struct {
	Key   string
	Value string
}

type Result struct {
	Name   CheckName
	Status Status
	Err    error
	Attrs  []Attr
}

// Reported is false for an Unknown result without an error: the component has
// not reported on the check yet.
func (r Result) Reported() bool {
	return r.Status != StatusUnknown || r.Err != nil
}

func (r Result) Equal(other Result) bool {
	return r.Name == other.Name &&
		r.Status == other.Status &&
		equalError(r.Err, other.Err) &&
		slices.Equal(r.Attrs, other.Attrs)
}

func equalError(a, b error) bool {
	if a == nil || b == nil {
		return a == b //nolint:errorlint
	}
	return a.Error() == b.Error()
}
