package upstream

import (
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// parseAllowed lists the provider code that parses a URL from a non-constant
// string, and why that string cannot carry a request path that would be
// decoded a second time. Keyed by "<path under provider/>:<owner>", the owner
// being the top-level function, or the package-level variable whose value
// (a function literal in a spec, say) holds the call.
var parseAllowed = map[string]string{
	"ovh/provider.go:s3Host":                      "operator-configured URL, only its host is used",
	"msgraph/provider.go:checkGraphURL":           "operator-configured URL, validated",
	"mcp_aws/provider.go:resolveConfig":           "operator-configured URL",
	"aws/path_gateway.go:processRequest":          "only scheme and host are taken; the path is the request's own or TransformedPath with its encoding",
	"sdk/sigv4/sigv4.go:ForwardDirectOpts":        "re-serializes an already-built *url.URL, which round-trips",
	"sdk/dualgateway/gateway.go:handleAPIRequest": "re-serializes the *url.URL upstream.URL built, then sets it as is",
}

// urlParsers maps each function or method that turns a string into a URL, or
// sends a request to one, to the index of that string among its arguments.
var urlParsers = map[string]int{
	"net/url.Parse":                  0,
	"net/url.ParseRequestURI":        0,
	"(*net/url.URL).Parse":           0,
	"net/http.NewRequest":            1,
	"net/http.NewRequestWithContext": 2,
	"net/http.Get":                   0,
	"net/http.Head":                  0,
	"net/http.Post":                  0,
	"net/http.PostForm":              0,
	"(*net/http.Client).Get":         0,
	"(*net/http.Client).Head":        0,
	"(*net/http.Client).Post":        0,
	"(*net/http.Client).PostForm":    0,
}

// TestProvidersParseOnlyReviewedURLs guards the bug class this package
// removes: a provider that builds an upstream URL as a string and parses it
// decodes the request path a second time, so the upstream can receive a path
// other than the one the request was authorized on. Build the URL with URL
// instead.
//
// Every call under provider/ that parses a URL from a non-constant string must
// be listed in parseAllowed with the reason it is safe, so a new one is a
// reviewed choice. Calls are matched by type, so an aliased import or a method
// on a *url.URL or *http.Client is seen, and every top-level declaration is
// walked, function literals in package-level variables included.
func TestProvidersParseOnlyReviewedURLs(t *testing.T) {
	root := moduleRoot(t)
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo,
		Dir: root,
	}
	pkgs, err := packages.Load(cfg, "./provider/...")
	if err != nil {
		t.Fatal(err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("%d errors loading the providers", n)
	}

	providerDir := filepath.Join(root, "provider")
	seen := map[string]bool{}
	files := 0
	for _, pkg := range pkgs {
		for _, f := range pkg.Syntax {
			path := pkg.Fset.File(f.Pos()).Name()
			rel, err := filepath.Rel(providerDir, path)
			if err != nil {
				t.Fatal(err)
			}
			rel = filepath.ToSlash(rel)
			if strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "sdk/upstream/") {
				continue
			}
			files++
			for _, decl := range f.Decls {
				owner := declOwner(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					arg := urlArgument(pkg.TypesInfo, call)
					if arg == nil {
						return true
					}
					if tv, ok := pkg.TypesInfo.Types[arg]; ok && tv.Value != nil {
						return true // a constant
					}
					key := rel + ":" + owner
					if _, ok := parseAllowed[key]; !ok {
						t.Errorf("%s: %s parses a URL from a string; build it with upstream.URL, or list %q in parseAllowed with the reason it is safe",
							pkg.Fset.Position(call.Pos()), owner, key)
					}
					seen[key] = true
					return true
				})
			}
		}
	}
	if files < 50 {
		t.Fatalf("checked %d files; the provider load is broken", files)
	}
	for key := range parseAllowed {
		if !seen[key] {
			t.Errorf("parseAllowed lists %q, which parses no URL from a string any more; remove it", key)
		}
	}
}

// declOwner names a top-level declaration: a function by its name, a variable
// or constant declaration by its first name.
func declOwner(decl ast.Decl) string {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return d.Name.Name
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
				return vs.Names[0].Name
			}
		}
	}
	return "?"
}

// urlArgument returns the URL argument of a call to one of urlParsers, or nil.
func urlArgument(info *types.Info, call *ast.CallExpr) ast.Expr {
	var id *ast.Ident
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		id = fn.Sel
	case *ast.Ident:
		id = fn // a dot import
	default:
		return nil
	}
	f, ok := info.Uses[id].(*types.Func)
	if !ok {
		return nil
	}
	i, ok := urlParsers[f.FullName()]
	if !ok || i >= len(call.Args) {
		return nil
	}
	return call.Args[i]
}

// moduleRoot returns the directory holding go.mod, walking up from the test's.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
