package helper

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// removedRoleNames are the auth role types, matchers and metadata extractors
// removed with auth roles. A role is granted per request by the namespace's
// groups over an admission's facts; none of these has a caller left, and a
// new one would bring a second, unaudited way to decide what a credential may
// do.
var removedRoleNames = []string{
	// role types
	"JWTRole", "CertRole", "KubernetesRole", "SPIFFERole",
	// matchers
	"matchRole", "validateJWTForRole",
	"validateCertConstraints", "verifyCertForRole", "certSatisfiesRole",
	"matchesGlob", "matchesAnyGlob", "matchesAnyExact",
	"matchRoleBindings", "matchBoundList", "audienceMatches", "onlyWildcardOrEmpty",
	"roleAcceptsSVID", "VerifyX509SVID", "VerifyJWTSVID", "CheckRoleBinding",
	"MatchPattern", "ValidatePattern",
	// metadata extractors and their field lists
	"extractCertMetadata", "certFieldValue", "validCertMetadataFields",
	"extractK8sMetadata", "validK8sMetadataFields",
	"extractSPIFFEIDMetadata", "mergeStringMaps", "validSPIFFEMetadataFields",
	"resolveGroupPolicies", "extractGroupsClaim",
	// the role endpoint's schema
	"legacyRolePath",
}

// removedAuthRoleNames are removed role code whose names are generic enough
// that unrelated code elsewhere may use them again: banned under auth/ only.
var removedAuthRoleNames = []string{"MatchAny", "extractMetadata", "resolveAudience"}

// removedRolePackages are the client packages that logged in with an auth
// role.
var removedRolePackages = []string{
	"github.com/stephnangue/warden/api/auth/jwt",
	"github.com/stephnangue/warden/api/auth/cert",
}

// No Go file under auth/, api/ or core/, tests included, names a removed auth
// role type, matcher or extractor (the generic names, under auth/ only), or
// imports a removed role-login package.
func TestRemovedRoleCodeStaysGone(t *testing.T) {
	root := moduleRoot(t)
	self, err := filepath.Abs("roles_removed_test.go")
	if err != nil {
		t.Fatal(err)
	}
	banned := make(map[string]bool, len(removedRoleNames))
	for _, n := range removedRoleNames {
		banned[n] = true
	}
	bannedInAuth := make(map[string]bool, len(removedAuthRoleNames))
	for _, n := range removedAuthRoleNames {
		bannedInAuth[n] = true
	}

	fset := token.NewFileSet()
	files := 0
	for _, dir := range []string{"auth", "api", "core"} {
		inAuth := dir == "auth"
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || path == self {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			files++
			rel, _ := filepath.Rel(root, path)
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				for _, gone := range removedRolePackages {
					if p == gone {
						t.Errorf("%s imports %s, which was removed with auth roles", rel, p)
					}
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && (banned[id.Name] || inAuth && bannedInAuth[id.Name]) {
					t.Errorf("%s:%d names %s, which was removed with auth roles", rel, fset.Position(id.Pos()).Line, id.Name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files < 100 {
		t.Fatalf("walked %d files under auth/, api/ and core/; the walk is broken", files)
	}

	for _, p := range removedRolePackages {
		dir := filepath.Join(root, strings.TrimPrefix(p, "github.com/stephnangue/warden/"))
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("%s still exists", dir)
		}
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
