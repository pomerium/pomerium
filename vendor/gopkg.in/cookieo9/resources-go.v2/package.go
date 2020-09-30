package resources

import (
	"go/build"
	"os"
	"path/filepath"
	"runtime"
)

// Opens the source directory of the current package as a Bundle.
// The current package is the package of the code calling
// OpenCurrentPackage() (as determined by runtime.Caller())
func OpenCurrentPackage() (Bundle, error) {
	_, sfile, _, _ := runtime.Caller(1)
	if p, err := build.ImportDir(filepath.Dir(sfile), build.FindOnly); err == nil {
		return &packageBundle{OpenFS(p.Dir).(*fsBundle)}, nil
	} else {
		return nil, err
	}
	panic("Shouldn't Get Here!")
}

// OpenPackagePath returns a Bundle which accesses files
// in the source directory of the package named by the given
// import path.
//
// Bundles accessing packages support the Searcher and Lister
// interfaces.
func OpenPackage(import_path string) (Bundle, error) {
	pkg, err := build.Import(import_path, "", build.FindOnly)
	if err != nil {
		return nil, err
	}
	return &packageBundle{OpenFS(pkg.Dir).(*fsBundle)}, nil
}

type packageBundle struct {
	*fsBundle
}

func (pb *packageBundle) List() ([]Resource, error) {
	var list []Resource
	err := filepath.Walk(pb.base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, err := filepath.Rel(pb.base, path)
			if err == nil {
				list = append(list, pb.file(filepath.ToSlash(rel)))
			}
		}
		return nil
	})
	return list, err
}
