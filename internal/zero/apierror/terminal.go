package apierror

import (
	"errors"
	"fmt"
)

// terminalError is an error that should not be retried
type terminalError struct {
	Err error
}

// Error implements error for terminalError
func (e *terminalError) Error() string {
	return fmt.Sprintf("terminal error: %v", e.Err)
}

// Unwrap implements errors.Unwrap for terminalError
func (e *terminalError) Unwrap() error {
	return e.Err
}

// Is implements errors.Is for terminalError
func (e *terminalError) Is(err error) bool {
	_, ok := err.(*terminalError)
	return ok
}

func (e *terminalError) IsTerminal() {}

// NewTerminalError creates a new terminal error that cannot be retried
func NewTerminalError(err error) error {
	return &terminalError{Err: err}
}

// IsTerminalError returns true if the error is a terminal error
func IsTerminalError(err error) bool {
	if err == nil {
		return false
	}
	var te *terminalError
	return errors.As(err, &te)
}
