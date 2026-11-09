package flight

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const singleflightPath = "golang.org/x/sync/singleflight"

// Every coalesced call in this module goes through Group, which applies the rules
// singleflight leaves to each caller (see the package comment). A direct import
// elsewhere would bypass them, the panic recovery among them, so it fails here.
func TestOnlyFlightImportsSingleflight(t *testing.T) {
	root := moduleRoot(t)
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata", "site":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || filepath.Dir(path) == self {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return nil // not this test's concern; the compiler reports it
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == singleflightPath {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s imports %s directly; coalesce through helper/flight instead", rel, singleflightPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// moduleRoot walks up from the package directory to the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the package directory")
		}
		dir = parent
	}
}
