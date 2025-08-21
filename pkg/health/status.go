package health

import "strings"

type Status int

const (
	StatusStarting Status = iota
	StatusRunning
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
