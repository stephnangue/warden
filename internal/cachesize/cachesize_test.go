package cachesize

import (
	"runtime"
	"strconv"
	"testing"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCounters(t *testing.T) {
	assert.Equal(t, int64(100_000), Counters(10_000))
	assert.Equal(t, int64(CountersPerEntry), Counters(0), "a cache holds at least one entry")
}

func TestMaxEntries(t *testing.T) {
	// 100 MiB of entries charged at least 328 bytes, plus ristretto's record.
	assert.Equal(t, int64(104_857_600/(328+RecordBytes)), MaxEntries(100<<20, 328))
	assert.Equal(t, int64(1), MaxEntries(10, 1_000), "at least one entry")
	assert.Equal(t, int64(10), MaxEntries(10*RecordBytes, -5), "a negative charge counts as none")
}

func TestBytes(t *testing.T) {
	cfg := Bytes[string, int](64<<20, 192)
	assert.Equal(t, int64(64<<20), cfg.MaxCost)
	// 67,108,864 / (192 + 56) = 270,600 entries, ten counters each.
	assert.Equal(t, int64(2_706_000), cfg.NumCounters)
	assert.False(t, cfg.IgnoreInternalCost)
}

func TestEntries(t *testing.T) {
	cfg := Entries[string, int](10_000)
	assert.Equal(t, int64(10_000), cfg.MaxCost)
	assert.Equal(t, int64(100_000), cfg.NumCounters)
	assert.True(t, cfg.IgnoreInternalCost)

	// No entries is refused by ristretto, not turned into a one-entry cache.
	_, err := ristretto.NewCache(Entries[string, int](0))
	assert.Error(t, err)
}

// fill sets n keys, each charged cost, and returns how many the cache kept.
// Ristretto applies Sets in order once Wait returns; under its 32K-deep set
// buffer none is dropped.
func fill(t *testing.T, c *ristretto.Cache[string, int], n int, cost int64) int {
	t.Helper()
	for i := range n {
		c.Set(strconv.Itoa(i), i, cost)
	}
	c.Wait()
	kept := 0
	for i := range n {
		if _, ok := c.Get(strconv.Itoa(i)); ok {
			kept++
		}
	}
	return kept
}

// An entry-bounded cache holds the number of entries it is configured for: a
// cost-1 entry is charged 1, not 1 plus ristretto's record.
func TestEntriesHoldsItsCount(t *testing.T) {
	c, err := ristretto.NewCache(Entries[string, int](1_000))
	require.NoError(t, err)
	defer c.Close()
	assert.Equal(t, 1_000, fill(t, c, 1_500, 1))
}

// RecordBytes is what ristretto really adds: a byte-bounded cache sized for
// exactly 100 entries of 200 bytes holds 100, not more and not fewer. A
// ristretto upgrade that changes its per-entry record fails here.
func TestRecordBytesMatchesRistretto(t *testing.T) {
	c, err := ristretto.NewCache(Bytes[string, int](100*(200+RecordBytes), 200))
	require.NoError(t, err)
	defer c.Close()
	assert.Equal(t, 100, fill(t, c, 150, 200))
}

// The counters are the cache's fixed cost, allocated when it is built: a
// 273,066-entry cache takes about 12 MiB.
func TestCountersMemory(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	c, err := ristretto.NewCache(Entries[string, int](273_066))
	require.NoError(t, err)
	defer c.Close()
	runtime.ReadMemStats(&after)
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("counters for 273,066 entries: %.1f MiB", float64(grew)/(1<<20))
	assert.Less(t, grew, int64(16<<20))
}
