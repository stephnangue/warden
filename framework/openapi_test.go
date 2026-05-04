// Ported from github.com/openbao/openbao/sdk/v2/framework/openapi_test.go.
// Tests that depended on upstream-only types (logical.Secret, wrapping types,
// logical.Paths fields warden doesn't have) and on golden-file fixtures are
// omitted; warden covers equivalent behavior with endpoint-level tests against
// the running server.

package framework

import (
	"reflect"
	"regexp"
	"sort"
	"testing"

	"github.com/stephnangue/warden/logical"
)

func TestOpenAPI_Regex(t *testing.T) {
	t.Run("Path fields", func(t *testing.T) {
		input := `/foo/bar/{inner}/baz/{outer}`

		matches := pathFieldsRe.FindAllStringSubmatch(input, -1)

		exp1 := "inner"
		exp2 := "outer"
		if matches[0][1] != exp1 || matches[1][1] != exp2 {
			t.Fatalf("Capture error. Expected %s and %s, got %v", exp1, exp2, matches)
		}

		input = `/foo/bar/inner/baz/outer`
		matches = pathFieldsRe.FindAllStringSubmatch(input, -1)

		if matches != nil {
			t.Fatalf("Expected nil match (%s), got %+v", input, matches)
		}
	})
	t.Run("Filtering", func(t *testing.T) {
		tests := []struct {
			input  string
			regex  *regexp.Regexp
			output string
		}{
			{
				input:  `abcde`,
				regex:  wsRe,
				output: "abcde",
			},
			{
				input:  `  a         b    cd   e   `,
				regex:  wsRe,
				output: "abcde",
			},
		}

		for _, test := range tests {
			result := test.regex.ReplaceAllString(test.input, "")
			if result != test.output {
				t.Fatalf("Clean Regex error (%s). Expected %s, got %s", test.input, test.output, result)
			}
		}
	})
}

func TestOpenAPI_ExpandPattern(t *testing.T) {
	tests := []struct {
		inPattern   string
		outPathlets []string
	}{
		// A simple string without regexp metacharacters passes through as is
		{"rotate/root/backup", []string{"rotate/root/backup"}},
		// A trailing regexp anchor metacharacter is removed
		{"rotate/root/backup$", []string{"rotate/root/backup"}},
		// As is a leading one
		{"^rotate/root/backup", []string{"rotate/root/backup"}},
		// Named capture groups become OpenAPI parameters
		{"auth/(?P<path>.+?)/tune$", []string{"auth/{path}/tune"}},
		{"auth/(?P<path>.+?)/tune/(?P<more>.*?)$", []string{"auth/{path}/tune/{more}"}},
		// Even if the capture group contains very complex regexp structure inside it
		{"something/(?P<something>(a|b(c|d))|e+|f{1,3}[ghi-k]?.*)", []string{"something/{something}"}},
		// A question-mark results in a result without and with the optional path part
		{"tools/hash(/(?P<urlalgorithm>.+))?", []string{
			"tools/hash",
			"tools/hash/{urlalgorithm}",
		}},
		// Multiple question-marks evaluate each possible combination
		{"(leases/)?renew(/(?P<url_lease_id>.+))?", []string{
			"leases/renew",
			"leases/renew/{url_lease_id}",
			"renew",
			"renew/{url_lease_id}",
		}},
		// GenericNameRegex is one particular way of writing a named capture group, so behaves the same
		{`config/ui/headers/` + GenericNameRegex("header"), []string{"config/ui/headers/{header}"}},
		// The question-mark behaviour is still works when the question-mark is directly applied to a named capture group
		{`leases/lookup/(?P<prefix>.+?)?`, []string{
			"leases/lookup/",
			"leases/lookup/{prefix}",
		}},
		// Optional trailing slashes at the end of the path get stripped - even if appearing deep inside an alternation
		{`(raw/?$|raw/(?P<path>.+))`, []string{
			"raw",
			"raw/{path}",
		}},
		// OptionalParamRegex is also another way of writing a named capture group, that is optional
		{"lookup" + OptionalParamRegex("urltoken"), []string{
			"lookup",
			"lookup/{urltoken}",
		}},
		// Optional trailing slashes at the end of the path get stripped in simpler cases too
		{"roles/?$", []string{
			"roles",
		}},
		{"roles/?", []string{
			"roles",
		}},
		// Non-optional trailing slashes remain... although don't do this, it breaks HelpOperation.
		{"accessors/$", []string{
			"accessors/",
		}},
		// GenericNameRegex and OptionalParamRegex still work when concatenated
		{"verify/" + GenericNameRegex("name") + OptionalParamRegex("urlalgorithm"), []string{
			"verify/{name}",
			"verify/{name}/{urlalgorithm}",
		}},
		// Named capture groups that specify enum-like parameters work as expected
		{"^plugins/catalog/(?P<type>auth|database|secret)/(?P<name>.+)$", []string{
			"plugins/catalog/{type}/{name}",
		}},
		{"^plugins/catalog/(?P<type>auth|database|secret)/?$", []string{
			"plugins/catalog/{type}",
		}},
		// Alternations between various literal path segments work
		{"(pathOne|pathTwo)/", []string{"pathOne/", "pathTwo/"}},
		{"(pathOne|pathTwo)/" + GenericNameRegex("name"), []string{"pathOne/{name}", "pathTwo/{name}"}},
		{
			"(pathOne|path-2|Path_3)/" + GenericNameRegex("name"),
			[]string{"Path_3/{name}", "path-2/{name}", "pathOne/{name}"},
		},
		// They still work when combined with GenericNameWithAtRegex
		{"(creds|sts)/" + GenericNameWithAtRegex("name"), []string{
			"creds/{name}",
			"sts/{name}",
		}},
		// And when they're somewhere other than the start of the pattern
		{"keys/generate/(internal|exported|kms)", []string{
			"keys/generate/exported",
			"keys/generate/internal",
			"keys/generate/kms",
		}},
		// Singular and plural list-operation patterns expand to two paths
		{"rolesets?/?", []string{"roleset", "rolesets"}},
		// Complex nested alternation and question-marks are correctly interpreted
		{"crl(/pem|/delta(/pem)?)?", []string{"crl", "crl/delta", "crl/delta/pem", "crl/pem"}},
	}

	for i, test := range tests {
		out, err := expandPattern(test.inPattern)
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(out)
		if !reflect.DeepEqual(out, test.outPathlets) {
			t.Fatalf("Test %d: Expected %v got %v", i, test.outPathlets, out)
		}
	}
}

func TestOpenAPI_ExpandPattern_ReturnsError(t *testing.T) {
	tests := []struct {
		inPattern string
		outError  error
	}{
		// None of these regexp constructs are allowed outside of named capture groups.
		{"[a-z]", errUnsupportableRegexpOperationForOpenAPI},
		{".", errUnsupportableRegexpOperationForOpenAPI},
		{"a+", errUnsupportableRegexpOperationForOpenAPI},
		{"a*", errUnsupportableRegexpOperationForOpenAPI},
		// Combinations of the above are also rejected.
		{".*", errUnsupportableRegexpOperationForOpenAPI},
	}

	for i, test := range tests {
		_, err := expandPattern(test.inPattern)
		if err != test.outError {
			t.Fatalf("Test %d: Expected %q got %q", i, test.outError, err)
		}
	}
}

func TestOpenAPI_SplitFields(t *testing.T) {
	fields := map[string]*FieldSchema{
		"a": {Description: "path"},
		"b": {Description: "body"},
		"c": {Description: "body"},
		"d": {Description: "body"},
		"e": {Description: "path"},
	}

	pathFields, bodyFields := splitFields(fields, "some/{a}/path/{e}")

	lp := len(pathFields)
	lb := len(bodyFields)
	l := len(fields)
	if lp+lb != l {
		t.Fatalf("split length error: %d + %d != %d", lp, lb, l)
	}

	for name, field := range pathFields {
		if field.Description != "path" {
			t.Fatalf("expected field %s to be in 'path', found in %s", name, field.Description)
		}
	}
	for name, field := range bodyFields {
		if field.Description != "body" {
			t.Fatalf("expected field %s to be in 'body', found in %s", name, field.Description)
		}
	}
}

func TestOpenAPI_hyphenatedToTitleCase(t *testing.T) {
	tests := map[string]struct {
		in       string
		expected string
	}{
		"simple": {
			in:       "test",
			expected: "Test",
		},
		"two-words": {
			in:       "two-words",
			expected: "TwoWords",
		},
		"three-words": {
			in:       "one-two-three",
			expected: "OneTwoThree",
		},
		"not-hyphenated": {
			in:       "something_like_this",
			expected: "Something_like_this",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			actual := hyphenatedToTitleCase(test.in)
			if actual != test.expected {
				t.Fatalf("expected: %s; got: %s", test.expected, actual)
			}
		})
	}
}

// TestDocumentPathsWithMountPrefix_PrependsMount confirms that the mount
// prefix is prepended to every path key in the resulting OAS doc, so multiple
// mounts with overlapping Pattern values produce distinct keys.
func TestDocumentPathsWithMountPrefix_PrependsMount(t *testing.T) {
	b := &Backend{
		BackendType:  "aws",
		BackendClass: logical.ClassProvider,
		Paths: []*Path{
			{
				Pattern: "config",
				Operations: map[logical.Operation]OperationHandler{
					logical.ReadOperation: &PathOperation{},
				},
				HelpSynopsis: "AWS config",
			},
			{
				Pattern: "role/" + GenericNameRegex("name"),
				Operations: map[logical.Operation]OperationHandler{
					logical.ReadOperation:   &PathOperation{},
					logical.UpdateOperation: &PathOperation{},
				},
				HelpSynopsis: "AWS role",
			},
		},
	}

	doc := NewOASDocument("test")
	if err := DocumentPathsWithMountPrefix(b, "aws/", doc); err != nil {
		t.Fatalf("DocumentPathsWithMountPrefix: %v", err)
	}

	want := []string{"/aws/config", "/aws/role/{name}"}
	got := pathKeysAny(doc)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %v; want %v", got, want)
	}
}

// TestDocumentPathsWithMountPrefix_DoesNotCollideAcrossMounts confirms that
// two backends with the same internal Pattern produce distinct keys after
// prefixing — the whole reason this wrapper exists.
func TestDocumentPathsWithMountPrefix_DoesNotCollideAcrossMounts(t *testing.T) {
	mk := func(name string) *Backend {
		return &Backend{
			BackendType:  name,
			BackendClass: logical.ClassProvider,
			Paths: []*Path{{
				Pattern: "config",
				Operations: map[logical.Operation]OperationHandler{
					logical.ReadOperation: &PathOperation{},
				},
				HelpSynopsis: name + " config",
			}},
		}
	}

	doc := NewOASDocument("test")
	if err := DocumentPathsWithMountPrefix(mk("aws"), "aws/", doc); err != nil {
		t.Fatalf("aws: %v", err)
	}
	if err := DocumentPathsWithMountPrefix(mk("azure"), "azure/", doc); err != nil {
		t.Fatalf("azure: %v", err)
	}

	if _, ok := doc.Paths["/aws/config"]; !ok {
		t.Errorf("missing /aws/config; have: %v", pathKeysAny(doc))
	}
	if _, ok := doc.Paths["/azure/config"]; !ok {
		t.Errorf("missing /azure/config; have: %v", pathKeysAny(doc))
	}
	if len(doc.Paths) != 2 {
		t.Errorf("paths = %d; want 2 — collision between mounts: %v", len(doc.Paths), pathKeysAny(doc))
	}
}

// TestDocumentPathsWithMountPrefix_NormalizesSlashes ensures both "x/" and "x"
// produce the same key form (no double slashes, no missing slash).
func TestDocumentPathsWithMountPrefix_NormalizesSlashes(t *testing.T) {
	b := &Backend{
		BackendType:  "x",
		BackendClass: logical.ClassProvider,
		Paths: []*Path{{
			Pattern: "config",
			Operations: map[logical.Operation]OperationHandler{
				logical.ReadOperation: &PathOperation{},
			},
			HelpSynopsis: "x",
		}},
	}

	for _, prefix := range []string{"x/", "x"} {
		doc := NewOASDocument("test")
		if err := DocumentPathsWithMountPrefix(b, prefix, doc); err != nil {
			t.Fatalf("prefix %q: %v", prefix, err)
		}
		if _, ok := doc.Paths["/x/config"]; !ok {
			t.Errorf("prefix %q produced unexpected paths: %v", prefix, pathKeysAny(doc))
		}
	}
}

// TestDocumentPathsWithMountPrefix_RejectsEmptyPrefix guards against silent
// malformed keys. Passing an empty mount prefix would produce paths like
// "//config" that conflict across mounts.
func TestDocumentPathsWithMountPrefix_RejectsEmptyPrefix(t *testing.T) {
	b := &Backend{
		BackendType:  "x",
		BackendClass: logical.ClassProvider,
		Paths: []*Path{{
			Pattern: "config",
			Operations: map[logical.Operation]OperationHandler{
				logical.ReadOperation: &PathOperation{},
			},
			HelpSynopsis: "x",
		}},
	}

	for _, prefix := range []string{"", "/", "//"} {
		doc := NewOASDocument("test")
		if err := DocumentPathsWithMountPrefix(b, prefix, doc); err == nil {
			t.Errorf("prefix %q: expected error, got nil; doc paths: %v", prefix, pathKeysAny(doc))
		}
	}
}

func pathKeysAny(doc *OASDocument) []string {
	ks := make([]string, 0, len(doc.Paths))
	for k := range doc.Paths {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
