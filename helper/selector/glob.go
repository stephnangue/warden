package selector

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// The glob dialect, the only one selectors use:
//
//	*    any run of characters except '/', possibly empty
//	**   any run of characters, '/' included, possibly empty
//	?    exactly one character except '/'
//	\x   the character x itself, so \* \? \\ are literal
//
// A run of three or more '*' reads as '**'. There are no character classes:
// '[' is an ordinary character. A trailing lone '\' is an error, and so is a
// pattern with more than MaxGlobStars single '*' between two '**'. A character
// is a UTF-8 encoded rune; a byte that is not valid UTF-8 counts as one
// character.

// IsPattern reports whether v holds an unescaped '*' or '?', and so is a glob
// rather than an exact value.
func IsPattern(v string) bool {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			i++
		case '*', '?':
			return true
		}
	}
	return false
}

// Unescape returns the exact value v writes: every "\x" becomes x. A trailing
// lone '\' is an error.
func Unescape(v string) (string, error) {
	if strings.IndexByte(v, '\\') < 0 {
		return v, nil
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\\' {
			if i+1 == len(v) {
				return "", errTrailingEscape
			}
			i++
			c = v[i]
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

var errTrailingEscape = errors.New(`trailing "\" escapes nothing`)

type tokenKind uint8

const (
	tokLiteral    tokenKind = iota // lit, byte for byte
	tokOne                         // ?
	tokStar                        // *
	tokDoubleStar                  // ** (any longer run of '*' too)
)

type token struct {
	kind tokenKind
	lit  string
	slot int // a '*' token's memo slot: its place among the '*' of its block
}

// MaxGlobStars bounds the single '*' of a glob between two '**' (or the start
// or end of the pattern). Each one has a memo slot in match.
const MaxGlobStars = 10

var errTooManyStars = fmt.Errorf("at most %d single '*' between '**'", MaxGlobStars)

// starSlots is the size of match's memo: one slot per '*' of a block.
const starSlots = MaxGlobStars

// Glob is a compiled pattern. It is immutable and safe for concurrent use.
type Glob struct {
	pattern string
	tokens  []token
}

// CompileGlob compiles pattern p.
func CompileGlob(p string) (*Glob, error) {
	g := &Glob{pattern: p}
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			g.tokens = append(g.tokens, token{kind: tokLiteral, lit: lit.String()})
			lit.Reset()
		}
	}
	stars := 0 // '*' tokens since the latest '**'
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '\\':
			if i+1 == len(p) {
				return nil, errTrailingEscape
			}
			i++
			lit.WriteByte(p[i])
		case '?':
			flush()
			g.tokens = append(g.tokens, token{kind: tokOne})
		case '*':
			flush()
			if i+1 < len(p) && p[i+1] == '*' {
				for i+1 < len(p) && p[i+1] == '*' {
					i++
				}
				g.tokens = append(g.tokens, token{kind: tokDoubleStar})
				stars = 0
				continue
			}
			if stars == MaxGlobStars {
				return nil, errTooManyStars
			}
			g.tokens = append(g.tokens, token{kind: tokStar, slot: stars})
			stars++
		default:
			lit.WriteByte(c)
		}
	}
	flush()
	return g, nil
}

// String returns the pattern g was compiled from.
func (g *Glob) String() string { return g.pattern }

// Match reports whether g matches all of v. It does not allocate.
func (g *Glob) Match(v string) bool { return match(g.tokens, v) }

// MatchBytes is Match over a byte slice, so a value rendered into a buffer is
// matched in place.
func (g *Glob) MatchBytes(v []byte) bool { return match(g.tokens, v) }

// match is a backtracking matcher. The pattern is a series of blocks separated
// by '**'; within a block, '*' and '?' never cross a '/'.
//
// It keeps two resume points: the latest '*' and the latest '**'. On a
// mismatch the latest '*' stretches by one character. Earlier '*' of the block
// are not revisited: the leftmost place for each segment between two '*' is as
// good as any later one, because a segment either holds no '/' (so a later
// place only shortens the '*' after it) or holds one (so it has a single
// possible place). Once a '**' is reached the blocks before it are settled:
// '**' absorbs anything, so the earliest end of a block is the best one.
//
// When the latest '*' cannot stretch, the block starts again one character
// after the latest '**', since a block's first segment may hold a '/' and then
// its leftmost place is not always the best. Every restart reaches each '*' of
// the block no earlier than the attempts before it, and two rules use that to
// keep restarts from repeating work. A '*' that ran to the end of v without
// meeting a '/' fails the whole match. And reach records, per '*', how far its
// run went in an earlier attempt: a restart that reaches that '*' no further on
// would retrace that attempt, so it is abandoned at once.
//
// Every '*' has a slot in reach (CompileGlob refuses more than MaxGlobStars per
// block), so a restart either stops at the first '*' it reaches too early or
// stretches that '*' over characters no earlier attempt stretched it over. Each
// stretch re-checks at most the rest of the pattern, so a match costs
// O(len(v) * len(pattern)).
func match[T string | []byte](tokens []token, v T) bool {
	ti, vi := 0, 0
	starT, starV, starSlot := -1, 0, 0 // the token after the latest '*' (-1: none), where its run ends, its slot
	dstarT, dstarV := -1, 0            // the token after the latest '**' (-1: none), where the block restarts
	var reach [starSlots]int           // per slot: 1 + where that '*' ran to; 0 when unknown
	for {
		if ti < len(tokens) {
			t := &tokens[ti]
			switch t.kind {
			case tokLiteral:
				if hasLiteral(v, vi, t.lit) {
					ti++
					vi += len(t.lit)
					continue
				}
			case tokOne:
				if vi < len(v) && v[vi] != '/' {
					ti++
					vi += charLen(v, vi)
					continue
				}
			case tokStar:
				if starT >= 0 {
					reach[starSlot] = starV + 1 // the previous '*' settled here
				}
				starT = -1
				if dstarT >= 0 && vi < reach[t.slot] {
					break // an earlier attempt already ran this '*' from here on
				}
				ti++
				starT, starV, starSlot = ti, vi, t.slot
				continue
			case tokDoubleStar:
				ti++
				if ti == len(tokens) {
					return true // a trailing '**' takes whatever is left
				}
				dstarT, dstarV = ti, vi
				starT = -1
				reach = [starSlots]int{}
				continue
			}
		} else if vi == len(v) {
			return true
		}

		// Mismatch: stretch the latest '*' by one character, if it can.
		if starT >= 0 {
			if starV < len(v) && v[starV] != '/' {
				starV += charLen(v, starV)
				ti, vi = starT, starV
				continue
			}
			if starV == len(v) {
				return false
			}
			reach[starSlot] = starV + 1 // stopped by the '/' at starV
			starT = -1
		}
		// Otherwise restart the block one character after the latest '**'.
		if dstarT >= 0 && dstarV < len(v) {
			dstarV += charLen(v, dstarV)
			ti, vi = dstarT, dstarV
			continue
		}
		return false
	}
}

// hasLiteral reports whether v holds lit at offset at.
func hasLiteral[T string | []byte](v T, at int, lit string) bool {
	if len(v)-at < len(lit) {
		return false
	}
	for i := 0; i < len(lit); i++ {
		if v[at+i] != lit[i] {
			return false
		}
	}
	return true
}

// charLen returns the byte length of the character at v[at]: its UTF-8
// encoding, or 1 for a byte that does not start a valid one.
func charLen[T string | []byte](v T, at int) int {
	if v[at] < utf8.RuneSelf {
		return 1
	}
	var buf [utf8.UTFMax]byte
	n := 0
	for n < len(buf) && at+n < len(v) {
		buf[n] = v[at+n]
		n++
	}
	_, size := utf8.DecodeRune(buf[:n])
	return size
}
