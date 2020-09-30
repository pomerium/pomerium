package resources

import (
	"io"
)

type autoBundle func() (Bundle, error)

func OpenAutoBundle(f func() (Bundle, error)) Bundle {
	return autoBundle(f)
}

func (ab autoBundle) Open(path string) (io.ReadCloser, error) {
	bundle, err := ab()
	if err != nil {
		return nil, err
	}
	return bundle.Open(path)
}

func (ab autoBundle) Close() error {
	bundle, err := ab()
	if err != nil {
		return err
	}
	return bundle.Close()
}

func (ab autoBundle) Find(path string) (Resource, error) {
	bundle, err := ab()
	if err != nil {
		return nil, err
	}
	if searcher, ok := bundle.(Searcher); ok {
		return searcher.Find(path)
	}
	return nil, ErrNotFound
}

func (ab autoBundle) Glob(pattern string) ([]Resource, error) {
	bundle, err := ab()
	if err != nil {
		return nil, err
	}
	if searcher, ok := bundle.(Searcher); ok {
		return searcher.Glob(pattern)
	}
	return nil, nil
}

func (ab autoBundle) List() ([]Resource, error) {
	bundle, err := ab()
	if err != nil {
		return nil, err
	}
	if lister, ok := bundle.(Lister); ok {
		return lister.List()
	}
	return nil, nil
}
