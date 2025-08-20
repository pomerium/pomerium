package health

import "strings"

type Status int

const (
	// StatusStarting indicates that a component must do some amount of initializing work
	StatusStarting Status = iota
	// StatusRunning indicates that the component has completed setup and is ready to run
	StatusRunning
	// StatusTerminating indicates that the component has started to shut down and is gracefully cleaning up
	StatusTerminating
)

func (s Status) String() string {
	v := "unknown"
	switch s {
	case StatusStarting:
		v = "starting"
	case StatusRunning:
		v = "running"
	case StatusTerminating:
		v = "terminating"
	}
	return strings.ToUpper(v)
}
