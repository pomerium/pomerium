// Package sessions handles the storage, management, and validation
// of pomerium user sessions.
package sessions

import (
	"errors"
	"net/http"
)

// SessionStore defines an interface for loading, saving, and clearing a session.
type SessionStore interface {
	SessionLoader
	ClearSession(http.ResponseWriter, *http.Request)
	SaveSession(http.ResponseWriter, *http.Request, any) error
}

// SessionLoader defines an interface for loading a session.
type SessionLoader interface {
	LoadSession(*http.Request) (string, error)
}

type multiSessionLoader []SessionLoader

func (l multiSessionLoader) LoadSession(r *http.Request) (string, error) {
	for _, ll := range l {
		s, err := ll.LoadSession(r)
		if errors.Is(err, ErrNoSessionFound) {
			continue
		}
		return s, err
	}
	return "", ErrNoSessionFound
}

// MultiSessionLoader returns a session loader that returns the first session available.
func MultiSessionLoader(loaders ...SessionLoader) SessionLoader {
	return multiSessionLoader(loaders)
}
