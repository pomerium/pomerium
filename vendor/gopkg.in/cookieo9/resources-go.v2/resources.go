package resources

import (
	"io"
	"os"
)

// A Bundle represents a collection of resources that can be streamed.
// The simple bundle only allows opening of known files, no searching
// or listing allowed.
//
// Paths to resources in bundles are platform independant, and should
// have directories delimeted by forward-slashes.
//
// Bundles provide a close method to release any os-resources they
// could be holding onto.
type Bundle interface {
	// Opens a resource for reading at path.
	// Returns ErrNotFound if file doesn't exist.
	Open(path string) (io.ReadCloser, error)

	// Release any os-resources needed to maintain bundle
	Close() error
}

// A Resource represents a streamable resource that has not yet been
// opened, but has been found in a searchable or listable bundle.
//
// Many bundle type have volatile resources, therefore in most
// cases Resource.Open must be checked for errors.
// (ie: There is no guarantee that the resource still exists
// between the call to Find/Glob/List and opening it)
type Resource interface {
	// Open the resource for reading.
	// Returns ErrNotFound if file missing.
	Open() (io.ReadCloser, error)

	// Get file information about the resource
	Stat() (os.FileInfo, error)

	// Get the platform independent path for this resource
	Path() string
}

// A Searcher represents an object where exact (Find) and
// pattern based (Glob) searches for resources can be made.
// The results of these operations are unopened Resources.
type Searcher interface {
	// Returns a Resource at the given path.
	// Returns ErrNotFound if no file exists.
	Find(path string) (Resource, error)

	// Returns all Resources matching the
	// given glob pattern.
	Glob(pattern string) ([]Resource, error)
}

// A Lister represents an object with a list of
// resources that can be iterated over.
type Lister interface {
	List() ([]Resource, error)
}
