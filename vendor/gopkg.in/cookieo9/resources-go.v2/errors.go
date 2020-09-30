package resources

import (
	"errors"
)

var (
	ErrNotFound    error = errors.New("resources: resource not found")
	ErrEscapeRoot  error = errors.New("resources: path escapes root")
	ErrNotRelative error = errors.New("resources: path not relative")
)
