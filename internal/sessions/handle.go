// Package sessions handles the storage, management, and validation
// of pomerium user sessions.
package sessions

import (
	"errors"
	"net/http"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

// HandleWriter defines an interface for writing and clearing a session.
type HandleWriter interface {
	ClearSessionHandle(http.ResponseWriter)
	WriteSessionHandle(http.ResponseWriter, *session.Handle) error
	WriteSessionHandleJWT(http.ResponseWriter, []byte) error
}

// HandleReader defines an interface for reading a session handle.
type HandleReader interface {
	ReadSessionHandle(*http.Request) (*session.Handle, error)
	ReadSessionHandleJWT(*http.Request) ([]byte, error)
}

// HandleReaderWriter is a HandleReader and a HandleWriter.
type HandleReaderWriter interface {
	HandleReader
	HandleWriter
}

type multiHandleReader []HandleReader

func (mhr multiHandleReader) ReadSessionHandle(r *http.Request) (*session.Handle, error) {
	for _, hr := range mhr {
		h, err := hr.ReadSessionHandle(r)
		if errors.Is(err, ErrNoSessionFound) {
			continue
		}
		return h, err
	}
	return nil, ErrNoSessionFound
}

func (mhr multiHandleReader) ReadSessionHandleJWT(r *http.Request) ([]byte, error) {
	for _, hr := range mhr {
		s, err := hr.ReadSessionHandleJWT(r)
		if errors.Is(err, ErrNoSessionFound) {
			continue
		}
		return s, err
	}
	return nil, ErrNoSessionFound
}

// MultiHandleReader returns a session handle reader that returns the first session handle available.
func MultiHandleReader(readers ...HandleReader) HandleReader {
	return multiHandleReader(readers)
}
