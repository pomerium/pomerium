package health

import "strings"

type Status int

const (
	// StatusUnkown indicates that a component has not reported any status
	StatusUnknown Status = iota
	// StatusRunning indicates that the component has completed setup and is ready to run
	StatusRunning
	// StatusTerminating indicates that the component has started to shut down and is gracefully cleaning up
	StatusTerminating
)

func (s Status) String() string {
	v := "unknown"
	switch s {
	case StatusRunning:
		v = "running"
	case StatusTerminating:
		v = "terminating"
	}
	return strings.ToUpper(v)
}

func (s Status) AsAttr() string {
	return strings.ToLower(s.String())
}
