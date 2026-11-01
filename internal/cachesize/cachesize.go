// Package cachesize derives a ristretto cache's configuration from what the
// cache bounds: a byte budget, each entry charged its approximate size, or a
// number of entries. Ristretto allocates its frequency counters up front from
// NumCounters, whatever the cache ends up holding, so the counters follow from
// the most entries the cache can hold rather than from a guess.
package cachesize

import "github.com/dgraph-io/ristretto/v2"

// CountersPerEntry is ristretto's guidance: ten frequency counters per entry a
// cache holds when full. The counters decide which entry a full cache evicts.
const CountersPerEntry = 10

// RecordBytes is what ristretto adds to the cost of every entry of a cache
// that does not ignore internal cost: the size of its per-entry record in
// ristretto v2.4.2. TestRecordBytesMatchesRistretto pins it.
const RecordBytes = 56

// bufferItems is the size of ristretto's per-goroutine buffer of key hits,
// its recommended value.
const bufferItems = 64

// The memory of a map[string]string, measured with Go 1.26: a non-nil map's
// header, and a group of eight slots for every eight entries, before the
// strings. TestStringMapBytesMatchesTheRuntime pins them.
const (
	mapHeaderBytes = 48
	mapGroupBytes  = 296
)

// StringMapBytes is the approximate memory of m, for a cost function: nothing
// when nil, else its header, its groups of slots and its strings. It
// allocates nothing.
func StringMapBytes(m map[string]string) int64 {
	if m == nil {
		return 0
	}
	n := mapHeaderBytes + int64((len(m)+7)/8)*mapGroupBytes
	for k, v := range m {
		n += int64(len(k) + len(v))
	}
	return n
}

// Counters returns the NumCounters of a cache that holds at most maxEntries.
func Counters(maxEntries int64) int64 {
	return CountersPerEntry * max(maxEntries, 1)
}

// MaxEntries returns how many entries a cache of maxBytes holds when every
// entry is charged minEntryBytes, the least any entry is charged; ristretto
// adds RecordBytes to each.
func MaxEntries(maxBytes, minEntryBytes int64) int64 {
	return max(maxBytes/(max(minEntryBytes, 0)+RecordBytes), 1)
}

// Bytes returns the config of a cache bounded to maxBytes, each Set charged
// the entry's approximate size, which is never less than minEntryBytes.
func Bytes[K ristretto.Key, V any](maxBytes, minEntryBytes int64) *ristretto.Config[K, V] {
	return &ristretto.Config[K, V]{
		NumCounters: Counters(MaxEntries(maxBytes, minEntryBytes)),
		MaxCost:     maxBytes,
		BufferItems: bufferItems,
	}
}

// Entries returns the config of a cache that holds at most maxEntries, each
// Set charged a cost of 1. A maxEntries below 1 is passed on as it is, so
// ristretto refuses the cache rather than building one that holds one entry.
func Entries[K ristretto.Key, V any](maxEntries int64) *ristretto.Config[K, V] {
	return &ristretto.Config[K, V]{
		NumCounters:        Counters(maxEntries),
		MaxCost:            maxEntries,
		BufferItems:        bufferItems,
		IgnoreInternalCost: true,
	}
}
