package retry

import (
	"errors"
	"fmt"
)

// TerminalError is an error that should not be retried
type TerminalError interface {
	error
	IsTerminal()
}

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
	//nolint:errorlint
	_, ok := err.(*terminalError)
	return ok
}

// IsTerminal implements TerminalError for terminalError
func (e *terminalError) IsTerminal() {}

// NewTerminalError creates a new terminal error that cannot be retried
func NewTerminalError(err error) error {
	return &terminalError{Err: err}
}

// IsTerminalError returns true if the error is a terminal error
func IsTerminalError(err error) bool {
	var te TerminalError
	return errors.As(err, &te)
}
