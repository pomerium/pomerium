package pebbleutil

import (
	"context"
	"fmt"
	"iter"
	"os"
	"slices"

	"github.com/cockroachdb/pebble/v2"
	"github.com/cockroachdb/pebble/v2/vfs"

	"github.com/pomerium/pomerium/internal/log"
)

// Iterate iterates over a pebble reader.
func Iterate[T any](src pebble.Reader, iterOptions *pebble.IterOptions, f func(it *pebble.Iterator) (T, error)) iter.Seq2[T, error] {
	var zero T
	return func(yield func(T, error) bool) {
		it, err := src.NewIter(iterOptions)
		if err != nil {
			yield(zero, err)
			return
		}

		for it.First(); it.Valid(); it.Next() {
			value, err := f(it)
			if err != nil {
				_ = it.Close()
				yield(zero, err)
				return
			}

			if !yield(value, nil) {
				_ = it.Close()
				return
			}
		}

		err = it.Error()
		if err != nil {
			_ = it.Close()
			yield(zero, err)
			return
		}

		err = it.Close()
		if err != nil {
			yield(zero, err)
			return
		}
	}
}

// IterateKeys yields the keys in a pebble reader.
func IterateKeys(src pebble.Reader, iterOptions *pebble.IterOptions) iter.Seq2[[]byte, error] {
	return Iterate(src, iterOptions, func(it *pebble.Iterator) ([]byte, error) {
		return slices.Clone(it.Key()), nil
	})
}

// IterateValues yields the values in a pebble reader.
func IterateValues(src pebble.Reader, iterOptions *pebble.IterOptions) iter.Seq2[[]byte, error] {
	return Iterate(src, iterOptions, func(it *pebble.Iterator) ([]byte, error) {
		value, err := it.ValueAndErr()
		if err != nil {
			return nil, err
		}
		return slices.Clone(value), nil
	})
}

// MustOpen opens a pebble database. It sets options useful for pomerium and panics if there is an error.
func MustOpen(dirname string, options *pebble.Options) *pebble.DB {
	db, err := Open(dirname, options)
	if err != nil {
		panic(err)
	}
	return db
}

// MustOpenMemory opens an in-memory pebble database. It panics if there is an error.
func MustOpenMemory(options *pebble.Options) *pebble.DB {
	if options == nil {
		options = new(pebble.Options)
	}
	options.FS = vfs.NewMem()
	return MustOpen("", options)
}

// Open opens a pebble database. It sets options useful for pomerium.
func Open(dirname string, options *pebble.Options) (*pebble.DB, error) {
	if options == nil {
		options = new(pebble.Options)
	}
	options.LoggerAndTracer = pebbleLogger{}
	eventListener := pebble.MakeLoggingEventListener(options.LoggerAndTracer)
	options.EventListener = &eventListener
	if options.FS == nil {
		options.FS = NewSecureFS(vfs.Default)
	}
	options.ApplyCompressionSettings(func() pebble.DBCompressionSettings {
		return pebble.DBCompressionBalanced
	})
	return pebble.Open(dirname, options)
}

// PrefixToUpperBound returns an upper bound for the given prefix.
func PrefixToUpperBound(prefix []byte) []byte {
	upperBound := make([]byte, len(prefix))
	copy(upperBound, prefix)
	for i := len(upperBound) - 1; i >= 0; i-- {
		upperBound[i] = upperBound[i] + 1
		if upperBound[i] != 0 {
			return upperBound[:i+1]
		}
	}
	return nil // no upper-bound
}

type pebbleLogger struct{}

func (pebbleLogger) Infof(msg string, args ...any) {
	log.Logger().Trace().Msgf("pebble: "+msg, args...)
}

func (pebbleLogger) Errorf(msg string, args ...any) {
	log.Error().Msgf("pebble: "+msg, args...)
}

func (pebbleLogger) Fatalf(msg string, args ...any) {
	log.Fatal().Msgf("pebble: "+msg, args...)
}

func (pebbleLogger) Eventf(ctx context.Context, msg string, args ...any) {
	log.Ctx(ctx).Trace().Msgf("pebble: "+msg, args...)
}

func (pebbleLogger) IsTracingEnabled(_ context.Context) bool { return false }

// enforce strict permissions on files (0600) and directories (0700)
type secureFS struct{ vfs.FS }

// NewSecureFS creates a new secure FS.
func NewSecureFS(underlying vfs.FS) vfs.FS {
	return secureFS{underlying}
}

func (s secureFS) Create(name string, category vfs.DiskWriteCategory) (vfs.File, error) {
	f, err := s.FS.Create(name, category)
	if err != nil {
		return nil, err
	}
	err = os.Chmod(name, 0o600)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return nil, fmt.Errorf("error setting file permissions %q: %w", name, err)
	}
	return f, nil
}

func (s secureFS) MkdirAll(path string, _ os.FileMode) error {
	return s.FS.MkdirAll(path, 0o700)
}

func (s secureFS) ReuseForWrite(oldname, newname string, category vfs.DiskWriteCategory) (vfs.File, error) {
	f, err := s.FS.ReuseForWrite(oldname, newname, category)
	if err != nil {
		return nil, err
	}
	err = os.Chmod(newname, 0o600)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("error setting file permissions %q: %w", newname, err)
	}
	return f, nil
}
