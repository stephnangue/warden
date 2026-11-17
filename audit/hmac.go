package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"sync"
)

// saltPrefix starts every salted value, and says how it was salted.
const saltPrefix = "hmac-sha256:"

// saltedLen is the length of a salted value: the prefix and the hex digest.
const saltedLen = len(saltPrefix) + 2*sha256.Size

// maxSaltScratch is the largest value whose scratch a pooled state keeps.
const maxSaltScratch = 4 << 10

// HMACer provides HMAC salting functionality
type HMACer struct {
	key []byte

	// states are the keyed hashes not in use. Keying a hash costs two rounds
	// of SHA-256 and a dozen allocations, which a pooled one has already paid.
	// The pool is this HMACer's own: a hash keyed for one device never salts
	// a value of another's.
	states sync.Pool
}

// saltState is a hash keyed and ready for a value, with the scratch a value
// needs on its way through it. One goroutine uses it at a time.
type saltState struct {
	mac hash.Hash
	// value holds the value as bytes: a hash takes no string.
	value []byte
	sum   [sha256.Size]byte
}

// NewHMACer creates a new HMACer with the given key
func NewHMACer(key string) *HMACer {
	return &HMACer{key: []byte(key)}
}

// state returns a keyed hash ready for a value: one the pool holds, or a new
// one.
func (h *HMACer) state() *saltState {
	if state, ok := h.states.Get().(*saltState); ok {
		return state
	}
	mac := hmac.New(sha256.New, h.key)
	// Reset once before any value goes through the hash. A reset is what
	// takes a value out of it, and the first one does less than the others:
	// it keeps what the hash last buffered, which would be the first value
	// salted.
	mac.Reset()
	return &saltState{mac: mac}
}

// AppendSalt appends the salted form of data to dst and returns the extended
// slice: "hmac-sha256:" and the HMAC-SHA256 of data under the key, in hex. An
// empty value has no salted form, and dst is returned as it was.
//
// It allocates nothing once dst has room, and may be called from several
// goroutines at once.
func (h *HMACer) AppendSalt(dst []byte, data string) []byte {
	if data == "" {
		return dst
	}

	state := h.state()
	state.value = append(state.value[:0], data...)
	// Writing to a hash never fails.
	state.mac.Write(state.value)
	dst = append(dst, saltPrefix...)
	dst = hex.AppendEncode(dst, state.mac.Sum(state.sum[:0]))

	// The value is what the salting hides: none of it stays in the pool. The
	// reset leaves the hash keyed for the next value and takes this one out
	// of it, by restoring the state the hash saved when it was first reset:
	// that is what the standard library's HMAC does over SHA-256, and what
	// this relies on.
	clear(state.value)
	state.mac.Reset()
	if cap(state.value) > maxSaltScratch {
		state.value = nil
	}
	h.states.Put(state)

	return dst
}

// Salt salts a string using HMAC-SHA256. It never fails: it returns an error
// to be a SaltFunc.
func (h *HMACer) Salt(ctx context.Context, data string) (string, error) {
	if data == "" {
		return "", nil
	}

	var salted [saltedLen]byte
	return string(h.AppendSalt(salted[:0], data)), nil
}

// SaltFunc returns a SaltFunc that uses this HMACer
func (h *HMACer) SaltFunc() SaltFunc {
	return func(ctx context.Context, data string) (string, error) {
		return h.Salt(ctx, data)
	}
}
