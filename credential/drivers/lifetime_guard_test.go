package drivers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A lease or expiry built from expires_in by hand has wrapped past its cap,
// served a token past its expiry for want of a buffer, and cached a token with no
// expires_in for a whole session. LeaseFromExpiresIn and ExpiryFromExpiresIn are
// the only conversions; this fails on any product of an expiry-named value and
// time.Second elsewhere in the module.
func TestExpiresInIsOnlyConvertedByTheLifetimeHelpers(t *testing.T) {
	root := lifetimeGuardModuleRoot(t)
	allowed := filepath.Join(root, "credential", "drivers", "oauth_token.go")

	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == allowed {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // the compiler reports it
		}
		ast.Inspect(file, func(n ast.Node) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if !ok || bin.Op != token.MUL {
				return true
			}
			if (namesAnExpiry(bin.X) && mentionsTimeSecond(bin.Y)) || (namesAnExpiry(bin.Y) && mentionsTimeSecond(bin.X)) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s:%d converts expires_in by hand; use LeaseFromExpiresIn or ExpiryFromExpiresIn",
					rel, fset.Position(bin.Pos()).Line)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// namesAnExpiry reports whether any identifier in e names an expiry (expires_in,
// ExpiresIn, expiry, expiration…), however it is wrapped: parentheses, a
// conversion, arithmetic on it.
func namesAnExpiry(e ast.Expr) bool {
	return anyNode(e, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		return ok && strings.Contains(strings.ToLower(id.Name), "expir")
	})
}

// mentionsTimeSecond reports whether e holds time.Second anywhere, so
// (time.Second) or time.Duration(1)*time.Second still count.
func mentionsTimeSecond(e ast.Expr) bool {
	return anyNode(e, func(n ast.Node) bool {
		sel, ok := n.(ast.Expr)
		return ok && isSelector(sel, "time", "Second")
	})
}

func anyNode(e ast.Expr, match func(ast.Node) bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if n != nil && match(n) {
			found = true
		}
		return !found
	})
	return found
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

func lifetimeGuardModuleRoot(t *testing.T) string {
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
