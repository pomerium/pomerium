package resources

import (
	"path/filepath"

	"github.com/kardianos/osext"
)

// ExecutablePath returns a system-native path to the currently running
// executable.
//
// NOTE: this function was intended to dissapear when it's functionality
// would be handled by the stdlib (go issue 4057). Since that is less
// likely to happen, I will probably leave this here leaving the API
// alone. It is supported via the "github.com/kardianos/osext" package.
func ExecutablePath() (string, error) {
	return osext.Executable()
}

// IsNotFound returns true if the error given is an error representing
// a Resource that was not found.
func IsNotFound(e error) bool {
	return e == ErrNotFound
}

// CheckPath() returns nil if given a valid path. Valid paths are
// forward slash delimeted, relative paths, which don't escape the
// base-level directory.
//
// Otherwise it returns one of the following error types:
//  - ErrEscapeRoot: if the path leaves the base directory
//  - ErrNotRelative: if the path is not a relative path
func CheckPath(path string) error {
	clean := filepath.Clean(path)
	if len(clean) >= 2 && clean[:2] == ".." {
		return ErrEscapeRoot
	}
	if len(clean) >= 1 && clean[0] == '/' {
		return ErrNotRelative
	}
	return nil
}
