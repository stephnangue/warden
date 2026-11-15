// Package jsonstrict finds what encoding/json accepts but the JSON an upstream
// reads may not agree with: an object key given twice.
//
// encoding/json keeps the last value of a repeated key. Other parsers keep the
// first, or refuse the document, so a body Warden's policy reads one way can reach
// an upstream that acts on another. RFC 8259 says names SHOULD be unique; I-JSON
// (RFC 7493 §2.3) says MUST.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"sync"
	"unicode/utf8"
)

const (
	// linearKeys is how many keys an object holds before its keys are looked up
	// in a map rather than compared one by one.
	linearKeys = 16

	// pooledCap bounds the scratch a scanner keeps in the pool, so one deep or
	// key-heavy document does not hold its memory for every later call.
	pooledCap = 1024
)

// DuplicateKey reports the first object key, in document order, that repeats
// within one object anywhere in data, decoded as encoding/json decodes it: "a" and
// "a" are one key, and so are two invalid UTF-8 spellings encoding/json turns
// into the same U+FFFD. data must be valid JSON — what json.Unmarshal accepts —
// for the answer to mean anything.
//
// A body whose keys are plain ASCII or valid UTF-8, without escapes, and whose
// objects hold at most 16 keys allocates nothing. Safe for concurrent use.
func DuplicateKey(data []byte) (string, bool) {
	s := scanners.Get().(*scanner)
	defer s.release()
	return s.scan(data)
}

var scanners = sync.Pool{New: func() any { return new(scanner) }}

// key is one object key: its raw bytes in data, or its decoded form when the raw
// bytes are not what encoding/json would produce.
type key struct {
	start, end int // data[start:end] is the key between its quotes
	decoded    int // index into scanner.decoded, or -1 when the raw bytes are the key
}

type frame struct {
	object    bool
	expectKey bool
	base      int                 // keys[base:] are this object's keys so far
	set       map[string]struct{} // this object's keys, once it holds more than linearKeys
}

type scanner struct {
	data    []byte
	frames  []frame
	keys    []key
	decoded []string
	// highFrames is the most frames held at once, so release clears every map a
	// pooled scanner could still reference.
	highFrames int
}

func (s *scanner) release() {
	if cap(s.frames) > pooledCap || cap(s.keys) > pooledCap || cap(s.decoded) > pooledCap {
		return
	}
	clear(s.frames[:s.highFrames])
	clear(s.decoded)
	s.data, s.frames, s.keys, s.decoded, s.highFrames = nil, s.frames[:0], s.keys[:0], s.decoded[:0], 0
	scanners.Put(s)
}

func (s *scanner) scan(data []byte) (string, bool) {
	s.data = data
	for i := 0; i < len(data); {
		switch data[i] {
		case '{':
			s.push(frame{object: true, expectKey: true, base: len(s.keys)})
			i++
		case '[':
			s.push(frame{base: len(s.keys)})
			i++
		case '}', ']':
			s.pop()
			i++
		case ',':
			if top := s.top(); top != nil && top.object {
				top.expectKey = true
			}
			i++
		case '"':
			end, plain := stringEnd(data, i)
			if top := s.top(); top != nil && top.object && top.expectKey {
				top.expectKey = false
				if k, dup := s.add(top, i+1, end-1, plain); dup {
					return k, true
				}
			}
			i = end
		default:
			// Whitespace, ':', and the bytes of numbers, true, false and null:
			// none of them opens or closes anything.
			i++
		}
	}
	return "", false
}

func (s *scanner) push(f frame) {
	s.frames = append(s.frames, f)
	s.highFrames = max(s.highFrames, len(s.frames))
}

func (s *scanner) pop() {
	if n := len(s.frames); n > 0 {
		f := &s.frames[n-1]
		s.keys = s.keys[:f.base]
		f.set = nil
		s.frames = s.frames[:n-1]
	}
}

func (s *scanner) top() *frame {
	if n := len(s.frames); n > 0 {
		return &s.frames[n-1]
	}
	return nil
}

// add records a key of the object f and reports it when f already holds it.
func (s *scanner) add(f *frame, start, end int, plain bool) (string, bool) {
	k := key{start: start, end: end, decoded: -1}
	if !plain {
		k.decoded = len(s.decoded)
		s.decoded = append(s.decoded, decodeKey(s.data[start-1:end+1]))
	}
	held := s.keys[f.base:]
	switch {
	case f.set != nil:
		name := s.text(k)
		if _, dup := f.set[name]; dup {
			return name, true
		}
		f.set[name] = struct{}{}
	case len(held) < linearKeys:
		for _, h := range held {
			if s.equal(h, k) {
				return s.text(k), true
			}
		}
	default:
		f.set = make(map[string]struct{}, 2*linearKeys)
		for _, h := range held {
			f.set[s.text(h)] = struct{}{}
		}
		name := s.text(k)
		if _, dup := f.set[name]; dup {
			return name, true
		}
		f.set[name] = struct{}{}
	}
	s.keys = append(s.keys, k)
	return "", false
}

// equal compares two keys as decoded, without allocating.
func (s *scanner) equal(a, b key) bool {
	switch {
	case a.decoded < 0 && b.decoded < 0:
		return bytes.Equal(s.data[a.start:a.end], s.data[b.start:b.end])
	case a.decoded < 0:
		return string(s.data[a.start:a.end]) == s.decoded[b.decoded]
	case b.decoded < 0:
		return s.decoded[a.decoded] == string(s.data[b.start:b.end])
	default:
		return s.decoded[a.decoded] == s.decoded[b.decoded]
	}
}

// text is the key as a string of its own.
func (s *scanner) text(k key) string {
	if k.decoded >= 0 {
		return s.decoded[k.decoded]
	}
	return string(s.data[k.start:k.end])
}

// stringEnd returns the index just past the string literal opening at data[i], and
// whether its bytes between the quotes are already what encoding/json decodes them
// to: no escape, and valid UTF-8.
func stringEnd(data []byte, i int) (end int, plain bool) {
	escaped, ascii := false, true
	j := i + 1
	for j < len(data) {
		switch c := data[j]; {
		case c == '\\':
			escaped = true
			j += 2
			continue
		case c == '"':
			body := data[i+1 : j]
			return j + 1, !escaped && (ascii || utf8.Valid(body))
		case c >= utf8.RuneSelf:
			ascii = false
		}
		j++
	}
	return len(data), false
}

// decodeKey decodes a quoted key exactly as encoding/json decodes an object key:
// escapes resolved, invalid UTF-8 and lone surrogates turned into U+FFFD.
func decodeKey(quoted []byte) string {
	var s string
	if err := json.Unmarshal(quoted, &s); err != nil {
		// Unreachable for valid JSON; the raw bytes are a key of their own.
		return string(quoted)
	}
	return s
}
