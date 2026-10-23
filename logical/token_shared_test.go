package logical

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// sharedTokenFields are the TokenEntry fields that Copy shares rather than
// copies: every per-request copy holds the same maps, slices and *Admission as
// the cached entry, and a role grant projects the role's policies and the
// cached membership's metadata into them. Reassigning one on a copy is safe;
// writing into one is a data race and leaks into every other request.
var sharedTokenFields = []string{"Data", "Metadata", "Policies", "Actors", "Admission"}

// freshEntryWriter is a function allowed to write into a shared field in
// place, because the entry it writes is one it is still building: no copy of
// it exists and no other goroutine can reach it.
type freshEntryWriter struct {
	file  string // module-relative path
	fn    string // "Func" or "Recv.Method"
	field string
}

// freshEntryWriters is the whole allowlist. An entry that no longer writes is
// an error, so the list cannot outlive the code it excuses.
var freshEntryWriters = []freshEntryWriter{
	// The token store's generateWithCollisionDetection hands Generate an entry
	// it has just built with a fresh Data map, before computing its ID and
	// before storing it in the cache: nothing else holds it yet.
	{file: "core/token_type_identity.go", fn: "IdentityTokenType.Generate", field: "Data"},
}

// mutatingFuncs are the library functions that write into their first
// argument (a map or a slice) in place.
var mutatingFuncs = map[string]map[string]bool{
	"maps": {"Copy": true, "DeleteFunc": true, "Insert": true},
	"slices": {
		"Sort": true, "SortFunc": true, "SortStableFunc": true, "Reverse": true,
		"Delete": true, "DeleteFunc": true, "Insert": true, "Replace": true,
		"Compact": true, "CompactFunc": true,
	},
	"sort": {
		"Strings": true, "Ints": true, "Float64s": true,
		"Sort": true, "Stable": true, "Slice": true, "SliceStable": true,
	},
}

// No non-test code writes into a TokenEntry's shared maps, slices or
// *Admission in place (Copy's contract), except the allowlisted creation
// sites. The check is type-based: it matches the fields of logical.TokenEntry
// (core's TokenEntry alias included) by their types.Var, never a same-named
// field of another type, and follows local variables that alias a shared
// field. A local counts as an alias if it ever holds one, wherever in the
// function: give a new map its own variable. What it cannot see: a shared
// field passed as an argument and written by the callee, or one stored into
// another struct and written from there.
func TestTokenEntrySharedFieldsNotMutatedInPlace(t *testing.T) {
	root := moduleRoot(t)
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports,
		Dir: root,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatal(err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("%d errors loading the module", n)
	}

	c := &mutationCheck{used: map[freshEntryWriter]bool{}}
	files := 0
	for _, pkg := range pkgs {
		for _, f := range pkg.Syntax {
			path := pkg.Fset.File(f.Pos()).Name()
			rel, err := filepath.Rel(root, path)
			if err != nil || strings.HasPrefix(rel, "e2e"+string(filepath.Separator)) || strings.HasSuffix(rel, "_test.go") {
				continue
			}
			files++
			c.checkFile(pkg.Fset, pkg.TypesInfo, filepath.ToSlash(rel), f)
		}
	}
	if files < 400 {
		t.Fatalf("checked %d files; the module load is broken", files)
	}
	if c.fields == nil {
		t.Fatal("logical.TokenEntry was never seen; the check matches nothing")
	}
	for _, v := range c.violations {
		t.Error(v)
	}
	for _, w := range freshEntryWriters {
		if !c.used[w] {
			t.Errorf("allowlist entry %s %s writes no %s any more: remove it", w.file, w.fn, w.field)
		}
	}
}

type mutationCheck struct {
	fields     map[*types.Var]string // TokenEntry's shared fields
	used       map[freshEntryWriter]bool
	violations []string

	// per file
	fset *token.FileSet
	info *types.Info
	file string

	// per function
	fn      string
	aliases map[*types.Var]bool
}

func (c *mutationCheck) checkFile(fset *token.FileSet, info *types.Info, file string, f *ast.File) {
	c.fset, c.info, c.file = fset, info, file
	c.learnFields()
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		c.fn = funcName(fd)
		c.aliases = map[*types.Var]bool{}
		c.collectAliases(fd.Body)
		ast.Inspect(fd.Body, c.visit)
	}
}

// learnFields finds logical.TokenEntry's shared fields among the objects the
// file's package knows. The first package that imports (or is) logical
// supplies them; go/packages type-checks logical once, so every package sees
// the same field objects.
func (c *mutationCheck) learnFields() {
	if c.fields != nil {
		return
	}
	for _, obj := range c.info.Uses {
		if obj.Pkg() == nil || obj.Pkg().Path() != reflect.TypeFor[TokenEntry]().PkgPath() {
			continue
		}
		te := obj.Pkg().Scope().Lookup("TokenEntry")
		if te == nil {
			continue
		}
		st := te.Type().Underlying().(*types.Struct)
		c.fields = map[*types.Var]string{}
		for i := range st.NumFields() {
			if f := st.Field(i); slices.Contains(sharedTokenFields, f.Name()) {
				c.fields[f] = f.Name()
			}
		}
		return
	}
}

// sharedField returns the TokenEntry field e holds, directly or through a
// local alias, a sub-slice, a conversion, & or *, or "" if none.
func (c *mutationCheck) sharedField(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.UnaryExpr:
			if x.Op != token.AND {
				return ""
			}
			e = x.X
		case *ast.CallExpr:
			// A conversion such as sort.StringSlice(te.Policies) shares.
			if tv, ok := c.info.Types[x.Fun]; !ok || !tv.IsType() || len(x.Args) != 1 {
				return ""
			}
			e = x.Args[0]
		case *ast.SelectorExpr:
			if sel := c.info.Selections[x]; sel != nil && sel.Kind() == types.FieldVal {
				if v, ok := sel.Obj().(*types.Var); ok {
					return c.fields[v]
				}
			}
			return ""
		case *ast.Ident:
			if v, ok := c.info.Uses[x].(*types.Var); ok && c.aliases[v] {
				return "alias"
			}
			return ""
		default:
			return ""
		}
	}
}

// collectAliases marks the local variables that ever hold a shared field (or
// a pointer into one), to a fixed point so an alias of an alias counts.
func (c *mutationCheck) collectAliases(body *ast.BlockStmt) {
	mark := func(lhs ast.Expr, rhs ast.Expr) bool {
		id, ok := lhs.(*ast.Ident)
		if !ok {
			return false
		}
		v, _ := c.info.ObjectOf(id).(*types.Var)
		if v == nil || c.aliases[v] {
			return false
		}
		// &te.Actors[i] points into the shared backing array.
		if u, ok := rhs.(*ast.UnaryExpr); ok && u.Op == token.AND {
			if ix, ok := u.X.(*ast.IndexExpr); ok {
				rhs = ix.X
			}
		}
		if c.sharedField(rhs) == "" {
			return false
		}
		c.aliases[v] = true
		return true
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i := range n.Lhs {
						changed = mark(n.Lhs[i], n.Rhs[i]) || changed
					}
				}
			case *ast.ValueSpec:
				if len(n.Names) == len(n.Values) {
					for i := range n.Names {
						changed = mark(n.Names[i], n.Values[i]) || changed
					}
				}
			}
			return true
		})
	}
}

func (c *mutationCheck) visit(n ast.Node) bool {
	switch n := n.(type) {
	case *ast.AssignStmt:
		for _, lhs := range n.Lhs {
			c.checkStore(lhs)
		}
		// te.F = append(te.F, ...) is caught as a call: append onto te.F.
	case *ast.IncDecStmt:
		c.checkStore(n.X)
	case *ast.CallExpr:
		c.checkCall(n)
	}
	return true
}

// checkStore reports a store that lands inside a shared field: below the
// stored location, an operand is one (te.Data[k], te.Actors[i].Name,
// te.Admission.MountPath, (*p)[k], alias[k]). Replacing the field itself
// (te.Data = m) or a local is fine.
func (c *mutationCheck) checkStore(lhs ast.Expr) {
	for e := lhs; ; {
		var next ast.Expr
		switch x := e.(type) {
		case *ast.ParenExpr:
			next = x.X
		case *ast.IndexExpr:
			next = x.X
		case *ast.SelectorExpr:
			next = x.X
		case *ast.StarExpr:
			next = x.X
		default:
			return
		}
		if f := c.sharedField(next); f != "" {
			c.report(lhs, f, "writes into")
			return
		}
		e = next
	}
}

func (c *mutationCheck) checkCall(call *ast.CallExpr) {
	if len(call.Args) == 0 {
		return
	}
	var name string
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		b, ok := c.info.Uses[fun].(*types.Builtin)
		if !ok {
			return
		}
		switch b.Name() {
		case "delete", "clear", "copy":
			name = b.Name()
		case "append":
			// A capped sub-slice (s[:n:n]) makes append reallocate.
			if s, ok := ast.Unparen(call.Args[0]).(*ast.SliceExpr); ok && s.Slice3 {
				return
			}
			name = "append"
		default:
			return
		}
	case *ast.SelectorExpr:
		f, ok := c.info.Uses[fun.Sel].(*types.Func)
		if !ok || f.Pkg() == nil || !mutatingFuncs[f.Pkg().Path()][f.Name()] {
			return
		}
		if sig, ok := f.Type().(*types.Signature); !ok || sig.Recv() != nil {
			return
		}
		name = f.Pkg().Path() + "." + f.Name()
	default:
		return
	}
	if f := c.sharedField(call.Args[0]); f != "" {
		c.report(call.Args[0], f, "calls "+name+" on")
	}
}

func (c *mutationCheck) report(at ast.Expr, field, what string) {
	if field != "alias" {
		w := freshEntryWriter{file: c.file, fn: c.fn, field: field}
		if slices.Contains(freshEntryWriters, w) {
			c.used[w] = true
			return
		}
	}
	pos := c.fset.Position(at.Pos())
	desc := "TokenEntry." + field
	if field == "alias" {
		desc = "a local alias of a TokenEntry shared field"
	}
	c.violations = append(c.violations, fmt.Sprintf("%s:%d: %s %s %s, which every copy of the entry shares: build a new value and reassign the field (see TokenEntry.Copy)",
		c.file, pos.Line, c.fn, what, desc))
}

func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
			continue
		case *ast.IndexExpr:
			t = x.X
			continue
		case *ast.IndexListExpr:
			t = x.X
			continue
		case *ast.Ident:
			return x.Name + "." + fd.Name.Name
		}
		return fd.Name.Name
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
