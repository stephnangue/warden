// Package factstest holds helpers for auth method tests: a selector.Source
// over an admission and a naming, as core builds one, drains that render what
// a fact yields, and checks that the removed auth roles stay gone. Only tests
// import it.
package factstest

import (
	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

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
