package core

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stephnangue/warden/logical"
)

// benchEntities returns n entries, each a governed agent claiming two native
// identities on one of four mounts, as a namespace of n agents would hold.
func benchEntities(n int) []*entityEntry {
	out := make([]*entityEntry, n)
	for i := range n {
		acc := fmt.Sprintf("auth_jwt_%08x", i%4)
		out[i] = newEntityEntry(&logical.Entity{
			ID:          fmt.Sprintf("00000000-0000-0000-0000-%012d", i),
			Name:        fmt.Sprintf("agent-%06d", i),
			Kind:        logical.EntityKindAgent,
			State:       logical.EntityStateActive,
			Description: "Reconciles supplier invoices against purchase orders",
			Sponsor:     benchSponsor,
			Aliases: []logical.EntityAlias{
				{MountAccessor: acc, Name: fmt.Sprintf("repo:corp/agent-%06d:ref:refs/heads/main", i)},
				{MountAccessor: "auth_k8s_00000001", Name: fmt.Sprintf("system:serviceaccount:agents:agent-%06d", i)},
			},
		})
	}
	return out
}

// benchSponsor is an accepted sponsor shared by every benchmark entity.
var benchSponsor = &logical.EntitySponsor{
	Type: logical.SponsorTypeGroup, Namespace: "root", GroupID: "4b1d6f6e-0000-0000-0000-000000000001", Group: "billing-leads",
	AddedBy:    logical.SponsorActor{MountAccessor: "auth_oidc_00000001", Alias: "0583c1a7-oid", Principal: "0583c1a7-oid"},
	AcceptedBy: logical.SponsorActor{MountAccessor: "auth_oidc_00000001", Alias: "0583c1a7-oid", Principal: "0583c1a7-oid"},
}

func noSkip(tb testing.TB) func(*entityEntry, error) {
	return func(en *entityEntry, err error) { tb.Fatalf("entity %s skipped: %v", en.Name, err) }
}

// BenchmarkEntities measures the entity index up to the per-namespace cap
// (logical.MaxEntitiesPerNamespace): the load at unseal, one claim (a write),
// the lock-free alias lookup, the claims counted on one mount, and a full
// listing walk. load reports what the index retains per entity, the entries
// excluded.
func BenchmarkEntities(b *testing.B) {
	for _, n := range []int{1_000, 10_000, logical.MaxEntitiesPerNamespace} {
		records := benchEntities(n)
		ents := loadEntities(records, noSkip(b))

		b.Run(fmt.Sprintf("load/n=%d", n), func(b *testing.B) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			kept := loadEntities(records, noSkip(b))
			runtime.GC()
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(kept)
			b.ReportAllocs()
			for b.Loop() {
				loadEntities(records, noSkip(b))
			}
			// Reported after the loop, which resets the metrics.
			b.ReportMetric((float64(after.HeapAlloc)-float64(before.HeapAlloc))/float64(n), "index-B/entity")
		})

		target := records[n/2]
		claimed := target.Clone()
		claimed.Aliases = append(claimed.Aliases, logical.EntityAlias{MountAccessor: "auth_cert_00000002", Name: "billing"})
		logical.SortAliases(claimed.Aliases)
		next := newEntityEntry(claimed)
		b.Run(fmt.Sprintf("claim/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := ents.with(entityChange{old: target, next: next}); err != nil {
					b.Fatal(err)
				}
			}
		})

		alias := target.Aliases[0]
		b.Run(fmt.Sprintf("byAlias/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if ents.byAlias(alias.MountAccessor, alias.Name) != target {
					b.Fatal("not found")
				}
			}
		})

		b.Run(fmt.Sprintf("aliasesOn/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if ents.aliasesOn(alias.MountAccessor) == 0 {
					b.Fatal("none counted")
				}
			}
		})

		b.Run(fmt.Sprintf("walk/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				seen := 0
				ents.all(func(*entityEntry) bool { seen++; return true })
				if seen != n {
					b.Fatal(seen)
				}
			}
		})
	}
}
