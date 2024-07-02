package log

import (
	"errors"
	"io"
	"slices"
	"sync"
)

// A MultiWriter dispatches writes to multiple writers.
type MultiWriter struct {
	mu sync.Mutex
	ws []io.Writer
}

// NewMultiWriter creates a new MultiWriter
func NewMultiWriter() *MultiWriter {
	return &MultiWriter{}
}

// Add adds a writer to the multi writer.
func (m *MultiWriter) Add(w io.Writer) {
	m.mu.Lock()
	m.ws = append(m.ws, w)
	m.mu.Unlock()
}

// Close closes the multi writer.
func (m *MultiWriter) Close() error {
	var err error
	m.mu.Lock()
	for _, w := range m.ws {
		if c, ok := w.(io.Closer); ok {
			err = errors.Join(err, c.Close())
		}
	}
	m.mu.Unlock()
	return err
}

// Remove removes a writer from the multi writer.
func (m *MultiWriter) Remove(w io.Writer) {
	m.mu.Lock()
	m.ws = slices.DeleteFunc(m.ws, func(mw io.Writer) bool {
		return mw == w
	})
	m.mu.Unlock()
}

// Write writes data to all the writers. The last count and error are returned.
func (m *MultiWriter) Write(data []byte) (int, error) {
	var n int
	var err error

	m.mu.Lock()
	for _, w := range m.ws {
		n, err = w.Write(data)
	}
	m.mu.Unlock()

	return n, err
}
