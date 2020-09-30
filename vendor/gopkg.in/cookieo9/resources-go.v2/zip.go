package resources

import (
	"archive/zip"
	"io"
	"os"
	"path"
)

type zipResource struct {
	*zip.File
}

func (zr *zipResource) Path() string {
	return zr.Name
}

func (zr *zipResource) Stat() (os.FileInfo, error) {
	return zr.FileInfo(), nil
}

func (zr *zipResource) String() string {
	return zr.Path()
}

type zipBundle struct {
	file *os.File
	rdr  *zip.Reader
}

// Closes the ZipBundle's associated file, if
// created by OpenZip, otherwise a no-op
func (zb *zipBundle) Close() error {
	if zb.file != nil {
		return zb.file.Close()
	}
	return nil
}

// Open the resource at path in the ZipBundle for reading.
// Returns ErrNotFound if no file exists with that path.
func (zb *zipBundle) Open(path string) (io.ReadCloser, error) {
	resource, err := zb.Find(path)
	if err != nil {
		return nil, err
	}
	return resource.Open()
}

// Finds the resource at path in the ZipBundle.
// Returns ErrNotFound if no file exists with that path.
func (zb *zipBundle) Find(path string) (Resource, error) {
	for _, file := range zb.rdr.File {
		if file.Name == path {
			return &zipResource{file}, nil
		}
	}
	return nil, ErrNotFound
}

// Finds all matching resources in the ZipBundle.
func (zb *zipBundle) Glob(pattern string) (resources []Resource, err error) {
	for _, file := range zb.rdr.File {
		if match, err := path.Match(pattern, file.Name); match {
			resources = append(resources, &zipResource{file})
		} else if err != nil {
			return nil, err
		}
	}
	return
}

// Lists all resources in the ZipBundle
func (zb *zipBundle) List() (list []Resource, err error) {
	for _, file := range zb.rdr.File {
		list = append(list, &zipResource{file})
	}
	return
}

// Opens a zipfile on disk as a bundle. You must call
// Close() to release the open file handle.
//
// Zip files opened as bundles implement the Bundle,
// Searcher, and Lister interfaces.
//
// If the file is in a known executable format,
// it is searched for an embedded zip file.
func OpenZip(path string) (Bundle, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	finfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	zb, err := OpenZipReader(file, finfo.Size())
	if err != nil {
		return nil, err
	}
	zb.(*zipBundle).file = file
	return zb, nil
}

// Opens a zipfile specified by the given ReaderAt and size.
// Close() is a no-op on the returned structure, ie: you must
// close the reader's resource yourself if necessary.
//
// Zip files opened as bundles implement the Bundle,
// Searcher, and Lister interfaces.
//
// If the reader accesses data for a known executable format,
// it will be searched for an embedded zip file.
func OpenZipReader(rda io.ReaderAt, size int64) (Bundle, error) {
	rdr, err := zip.NewReader(rda, size)
	if err != nil {
		rdr2, err2 := zipExeReader(rda, size)
		if err2 != nil {
			return nil, err
		}
		rdr = rdr2
	}
	return &zipBundle{rdr: rdr}, nil
}
