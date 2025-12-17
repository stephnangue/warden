package physical

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"

	iradix "github.com/hashicorp/go-immutable-radix"
	"golang.org/x/crypto/blake2b"
)

// Decodes/Unmarshals the given io.Reader pointing to a JSON, into a desired object
func DecodeJSONFromReader(r io.Reader, out interface{}) error {
	if r == nil {
		return errors.New("'io.Reader' being decoded is nil")
	}
	if out == nil {
		return errors.New("output parameter 'out' is nil")
	}

	dec := json.NewDecoder(r)

	// While decoding JSON values, interpret the integer values as `json.Number`s instead of `float64`.
	dec.UseNumber()

	// Since 'out' is an interface representing a pointer, pass it to the decoder without an '&'
	return dec.Decode(out)
}

func QuoteIdentifier(name string) string {
	end := strings.IndexRune(name, 0)
	if end > -1 {
		name = name[:end]
	}
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

const (
	LockCount = 256
)

type LockEntry struct {
	sync.RWMutex
}

// CreateLocks returns an array so that the locks can be iterated over in
// order.
//
// This is only threadsafe if a process is using a single lock, or iterating
// over the entire lock slice in order. Using a consistent order avoids
// deadlocks because you can never have the following:
//
// Lock A, Lock B
// Lock B, Lock A
//
// Where process 1 is now deadlocked trying to lock B, and process 2 deadlocked trying to lock A
func CreateLocks() []*LockEntry {
	ret := make([]*LockEntry, LockCount)
	for i := range ret {
		ret[i] = new(LockEntry)
	}
	return ret
}

func LockIndexForKey(key string) uint8 {
	return uint8(Blake2b256Hash(key)[0])
}

func LockForKey(locks []*LockEntry, key string) *LockEntry {
	return locks[LockIndexForKey(key)]
}

func LocksForKeys(locks []*LockEntry, keys []string) []*LockEntry {
	lockIndexes := make(map[uint8]struct{}, len(keys))
	for _, k := range keys {
		lockIndexes[LockIndexForKey(k)] = struct{}{}
	}

	locksToReturn := make([]*LockEntry, 0, len(keys))
	for i, l := range locks {
		if _, ok := lockIndexes[uint8(i)]; ok {
			locksToReturn = append(locksToReturn, l)
		}
	}

	return locksToReturn
}

func Blake2b256Hash(key string) []byte {
	hf, _ := blake2b.New256(nil)

	hf.Write([]byte(key))

	return hf.Sum(nil)
}

// PathManager is a prefix searchable index of paths
type PathManager struct {
	l     sync.RWMutex
	paths *iradix.Tree
}

// New creates a new path manager
func NewPathManager() *PathManager {
	return &PathManager{
		paths: iradix.New(),
	}
}

// AddPaths adds path to the paths list
func (p *PathManager) AddPaths(paths []string) {
	p.l.Lock()
	defer p.l.Unlock()

	txn := p.paths.Txn()
	for _, prefix := range paths {
		if len(prefix) == 0 {
			continue
		}

		var exception bool
		if strings.HasPrefix(prefix, "!") {
			prefix = strings.TrimPrefix(prefix, "!")
			exception = true
		}

		// We trim any trailing *, but we don't touch whether it is a trailing
		// slash or not since we want to be able to ignore prefixes that fully
		// specify a file
		txn.Insert([]byte(strings.TrimSuffix(prefix, "*")), exception)
	}
	p.paths = txn.Commit()
}

// RemovePaths removes paths from the paths list
func (p *PathManager) RemovePaths(paths []string) {
	p.l.Lock()
	defer p.l.Unlock()

	txn := p.paths.Txn()
	for _, prefix := range paths {
		if len(prefix) == 0 {
			continue
		}

		// Exceptions aren't stored with the leading ! so strip it
		prefix = strings.TrimPrefix(prefix, "!")

		// We trim any trailing *, but we don't touch whether it is a trailing
		// slash or not since we want to be able to ignore prefixes that fully
		// specify a file
		txn.Delete([]byte(strings.TrimSuffix(prefix, "*")))
	}
	p.paths = txn.Commit()
}

// RemovePathPrefix removes all paths with the given prefix
func (p *PathManager) RemovePathPrefix(prefix string) {
	p.l.Lock()
	defer p.l.Unlock()

	// We trim any trailing *, but we don't touch whether it is a trailing
	// slash or not since we want to be able to ignore prefixes that fully
	// specify a file
	p.paths, _ = p.paths.DeletePrefix([]byte(strings.TrimSuffix(prefix, "*")))
}

// Len returns the number of paths
func (p *PathManager) Len() int {
	return p.paths.Len()
}

// Paths returns the path list
func (p *PathManager) Paths() []string {
	p.l.RLock()
	defer p.l.RUnlock()

	paths := make([]string, 0, p.paths.Len())
	walkFn := func(k []byte, v interface{}) bool {
		paths = append(paths, string(k))
		return false
	}
	p.paths.Root().Walk(walkFn)
	return paths
}

// HasPath returns if the prefix for the path exists regardless if it is a path
// (ending with /) or a prefix for a leaf node
func (p *PathManager) HasPath(path string) bool {
	p.l.RLock()
	defer p.l.RUnlock()

	if _, exceptionRaw, ok := p.paths.Root().LongestPrefix([]byte(path)); ok {
		var exception bool
		if exceptionRaw != nil {
			exception = exceptionRaw.(bool)
		}
		return !exception
	}
	return false
}

// HasExactPath returns if the longest match is an exact match for the
// full path
func (p *PathManager) HasExactPath(path string) bool {
	p.l.RLock()
	defer p.l.RUnlock()

	if val, exceptionRaw, ok := p.paths.Root().LongestPrefix([]byte(path)); ok {
		var exception bool
		if exceptionRaw != nil {
			exception = exceptionRaw.(bool)
		}

		strVal := string(val)
		if strings.HasSuffix(strVal, "/") || strVal == path {
			return !exception
		}
	}
	return false
}

// HasPathSegments returns if the prefix for a given path exists,
// as long as full path components (delimited by '/') are matched.
func (p *PathManager) HasPathSegments(path string) bool {
	p.l.RLock()
	defer p.l.RUnlock()

	if val, exceptionRaw, ok := p.paths.Root().LongestPrefix([]byte(path)); ok {
		var exception bool
		if exceptionRaw != nil {
			exception = exceptionRaw.(bool)
		}

		strVal := string(val)
		if path == strVal || // exact match, down to the trailing '/'
			// prefix match is continued by a new path segment, where `strVal` has no trailing '/'
			path[len(strVal)] == '/' ||
			// prefix match is continued by a new path segment, where `strVal` has an trailing '/'
			// -- in this case we enforce the trailing '/' in `path` as well.
			(path[len(strVal)-1] == '/' && strVal[len(strVal)-1] == '/') {
			return !exception
		}
	}
	return false
}