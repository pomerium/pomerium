package resources

import (
	"io"
	"path/filepath"
)

// BundleSequences are meta-bundles which contain a slice
// of sub-bundles to test/access sequentially for resources.
//
// Nil bundles are skipped, instead of causing errors or panics.
type BundleSequence []Bundle

// Close() is a no-op for BundleSequences; you must close
// the sub-bundles yourself.
func (bs BundleSequence) Close() error {
	return nil
}

// Open finds the first sub-bundle where Open() doesn't return
// a ErrNotFound, and returns the io.ReadCloser.
//
// If any error other than ErrNotFound is seen, it is returned immediately.
func (bs BundleSequence) Open(path string) (io.ReadCloser, error) {
	for _, bundle := range bs {
		if bundle == nil {
			continue
		}
		reader, err := bundle.Open(path)
		if err == nil {
			return reader, nil
		} else if err != ErrNotFound {
			return nil, err
		}
	}
	return nil, ErrNotFound
}

// Find finds the first resource matching path in the sub-bundles.
// If multiple sub-bundles contain a resource a the given path, the
// resource from the earliest bundle is used.
//
// If any error other than ErrNotFound is seen, it is returned.
func (bs BundleSequence) Find(path string) (Resource, error) {
	for _, bundle := range bs {
		if bundle == nil {
			continue
		}
		if searchable, ok := bundle.(Searcher); ok {
			resource, err := searchable.Find(path)
			if err == nil {
				return resource, nil
			} else if err != ErrNotFound {
				return nil, err
			}
		}
	}
	return nil, ErrNotFound
}

// merge_resources merges two lists of resources and returns
// the resulting list. This operation is analgeous to append
// but doesn't append an element from extra into source if
// an element in source already exists with the same path.
func merge_resources(source, extra []Resource) []Resource {
	for _, e := range extra {
		found := false
		for _, s := range source {
			if s.Path() == e.Path() {
				found = true
				break
			}
		}
		if !found {
			source = append(source, e)
		}
	}
	return source
}

// Glob finds the collection of all resources in all the sub-bundles
// which match the given glob pattern.
// In the event that multiple resources matched have the same path,
// the one from the earliest sub-bundle will be shown, all others
// will be suppressed.
func (bs BundleSequence) Glob(pattern string) (matches []Resource, err error) {
	for _, bundle := range bs {
		if bundle == nil {
			continue
		}
		if searchable, ok := bundle.(Searcher); ok {
			resources, err := searchable.Glob(pattern)
			if err == nil {
				matches = merge_resources(matches, resources)
			} else if err != ErrNotFound {
				return nil, err
			}
		}
	}
	return
}

// List provides a slice containing all resources from all the sub-bundles.
// Should multiple bundles contain a resource at the same path, only the
// first resource (from the first sub-bundle) will be present in the list.
func (bs BundleSequence) List() (resources []Resource, err error) {
	for _, bundle := range bs {
		if bundle == nil {
			continue
		}
		if listable, ok := bundle.(Lister); ok {
			list, err := listable.List()
			if err != nil {
				return nil, err
			}
			resources = merge_resources(resources, list)
		}
	}
	return
}

// DefaultBundle represents a default search path of:
//  - The current working directory
//  - The directory containing the executable
//  - The package source-code directory
//  - The executable treated as a ZipBundle
var DefaultBundle BundleSequence

func init() {
	var cwd, cur_pkg, exe_dir, exe Bundle
	cwd = OpenFS(".")
	cur_pkg = OpenAutoBundle(OpenCurrentPackage)

	if exe_path, err := ExecutablePath(); err == nil {
		exe_dir = OpenFS(filepath.Dir(exe_path))
		if exe, err = OpenZip(exe_path); err == nil {
			DefaultBundle = append(DefaultBundle, exe)
		}
	}

	DefaultBundle = append(DefaultBundle, cwd, exe_dir, cur_pkg, exe)
}

// Open() is a shortcut for DefaultBundle.Open()
func Open(path string) (io.ReadCloser, error) {
	return DefaultBundle.Open(path)
}

// Find() is a shortcut for DefaultBundle.Find()
func Find(path string) (Resource, error) {
	return DefaultBundle.Find(path)
}

// Glob() is a shortcut for DefaultBundle.Glob()
func Glob(pattern string) ([]Resource, error) {
	return DefaultBundle.Glob(pattern)
}

// List() is a shortcut for DefaultBundle.List()
func List() ([]Resource, error) {
	return DefaultBundle.List()
}
