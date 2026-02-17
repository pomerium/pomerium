package cli

import "errors"

// ErrHandoff is a sentinel error to indicate that the command triggered a handoff,
// and we should not automatically disconnect
var ErrHandoff = errors.New("handoff")

// ErrDeleteSessionOnExit is a sentinel error to indicate that the authorized
// session should be deleted once the SSH connection ends.
var ErrDeleteSessionOnExit = errors.New("delete_session_on_exit")
