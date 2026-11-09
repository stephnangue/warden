//go:build race

package copybuf

// raceEnabled: under the race detector sync.Pool drops a share of what is put
// back, on purpose, so allocation counts are not meaningful.
const raceEnabled = true
