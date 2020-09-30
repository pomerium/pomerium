package resources

import (
	"io"
	"os"
	"path/filepath"
)

type fsResource struct {
	base string
	path string
}

func (f *fsResource) real_path() string {
	return filepath.Join(f.base, filepath.FromSlash(f.path))
}

func (f *fsResource) Path() string {
	return f.path
}

func (f *fsResource) Stat() (os.FileInfo, error) {
	return os.Stat(f.real_path())
}

func (f *fsResource) Open() (io.ReadCloser, error) {
	return os.Open(f.real_path())
}

func (f *fsResource) String() string {
	return f.path
}

type fsBundle struct {
	base string
}

func OpenFS(base_dir string) Bundle {
	base, err := filepath.Abs(filepath.Clean(base_dir))
	if err != nil {
		panic(err)
	}

	return &fsBundle{base: base}
}

func (fb *fsBundle) Close() error {
	return nil
}

func (fb *fsBundle) file(path string) Resource {
	return &fsResource{
		base: fb.base,
		path: path,
	}
}

func (fb *fsBundle) Open(path string) (io.ReadCloser, error) {
	if err := CheckPath(path); err != nil {
		return nil, err
	}

	return fb.file(path).Open()
}

func (fb *fsBundle) Find(path string) (Resource, error) {
	if err := CheckPath(path); err != nil {
		return nil, err
	}

	f := fb.file(path)
	if _, err := f.Stat(); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

func (fb *fsBundle) Glob(pattern string) ([]Resource, error) {
	if err := CheckPath(pattern); err != nil {
		return nil, err
	}

	pattern = filepath.Clean(filepath.FromSlash(pattern))
	pattern = fb.file(pattern).(*fsResource).real_path()
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	rsrcs := make([]Resource, len(matches))
	for i := range rsrcs {
		rel, err := filepath.Rel(fb.base, matches[i])
		if err != nil {
			return nil, err
		}

		path := filepath.ToSlash(rel)
		rsrcs[i] = fb.file(path)
	}
	return rsrcs, nil
}
