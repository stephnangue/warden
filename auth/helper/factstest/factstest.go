// Package factstest holds helpers for auth method tests: a selector.Source
// over an admission and a naming, as core builds one, drains that render what
// a fact yields, a reader for frozen case tables, the segment-pattern grammar
// of the removed auth roles, and checks that those roles stay gone. Only tests
// import it.
package factstest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// Frozen decodes testdata/<name>, a JSON array, into a slice of T. Such a file
// is a table of (input, outcome) cases recorded from code that no longer
// exists, so a test can keep checking that code's successor against what it
// decided. An unreadable or empty table fails the test.
func Frozen[T any](t testing.TB, name string) []T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("frozen table: %v", err)
	}
	var out []T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("frozen table %s: %v", name, err)
	}
	if len(out) == 0 {
		t.Fatalf("frozen table %s is empty", name)
	}
	return out
}

// SegmentPatternError reports why p is not a segment pattern as the removed
// auth roles accepted them in allowed_uri_sans and allowed_spiffe_ids: '+'
// one segment, '*' as the last segment one or more, "+*" forbidden, no empty
// body or segment ("scheme://*" and a bare "*" match everything). The role
// conversions in the method tests refuse what it refuses.
func SegmentPatternError(p string) error {
	if strings.Contains(p, "+*") {
		return fmt.Errorf("pattern %q: '+*' is forbidden", p)
	}
	body := p
	if _, rest, ok := strings.Cut(p, "://"); ok {
		body = rest
	}
	if body == "" {
		return fmt.Errorf("pattern %q: empty body", p)
	}
	if body == "*" {
		return nil
	}
	parts := strings.Split(body, "/")
	for i, s := range parts {
		if s == "" {
			return fmt.Errorf("pattern %q: empty segment at position %d", p, i)
		}
		if s == "*" && i != len(parts)-1 {
			return fmt.Errorf("pattern %q: '*' is only allowed as the last segment", p)
		}
	}
	return nil
}

// Source answers fact names from Adm under Naming, as core's matcher does:
// one naming for every lookup of an evaluation.
type Source struct {
	Adm    *logical.Admission
	Naming *logical.MountNaming
}

var _ selector.Source = Source{}

// Lookup implements selector.Source.
func (s Source) Lookup(name string) selector.Cursor { return s.Adm.Lookup(s.Naming, name) }

// Drain returns every value cur yields, rendered by selector.FormatScalar, or
// nil when it yields none.
func Drain(cur selector.Cursor) []string {
	var out []string
	for v, ok := cur.Next(); ok; v, ok = cur.Next() {
		out = append(out, string(selector.FormatScalar(nil, v)))
	}
	return out
}

// Values returns what adm answers for name under n, rendered (see Drain).
func Values(adm *logical.Admission, n *logical.MountNaming, name string) []string {
	return Drain(adm.Lookup(n, name))
}
