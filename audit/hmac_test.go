package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestHMACSalting(t *testing.T) {
	hmacer := NewHMACer("test-secret-key")

	input := "my-secret-token"
	salted, err := hmacer.Salt(context.Background(), input)
	if err != nil {
		t.Fatalf("Failed to salt data: %v", err)
	}

	// Check that salted value is different from input
	if salted == input {
		t.Error("Salted value should be different from input")
	}

	// Check that it has the correct prefix
	if len(salted) < 12 || salted[:12] != "hmac-sha256:" {
		t.Error("Salted value should have 'hmac-sha256:' prefix")
	}

	// Check that same input produces same output
	salted2, _ := hmacer.Salt(context.Background(), input)
	if salted != salted2 {
		t.Error("Same input should produce same salted output")
	}
}

func TestHMACerSaltFunc(t *testing.T) {
	h := NewHMACer("test-key")
	fn := h.SaltFunc()

	result, err := fn(context.Background(), "hello")
	if err != nil {
		t.Fatalf("SaltFunc failed: %v", err)
	}
	if result == "" || result == "hello" {
		t.Error("expected salted output")
	}
	if !containsSubstring(result, "hmac-sha256:") {
		t.Error("expected hmac-sha256: prefix")
	}

	// Empty string
	result, err = fn(context.Background(), "")
	if err != nil {
		t.Fatalf("SaltFunc empty failed: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty for empty input, got %s", result)
	}
}

// saltedWithNewHash is the salted form of value under key, computed with a
// hash made for the occasion: what Salt returned before it pooled its hashes.
func saltedWithNewHash(key, value string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// saltValues are values of the sizes a hash treats differently: shorter than
// its block, exactly one block, several blocks, and larger than the scratch a
// pooled hash keeps.
var saltValues = []string{
	"a",
	"my-secret-token",
	"ghs_16C7e42F292c6912E7710c838347Ae178B4a",
	strings.Repeat("b", sha256.BlockSize-1),
	strings.Repeat("c", sha256.BlockSize),
	strings.Repeat("d", sha256.BlockSize+1),
	strings.Repeat("e", 1000),
	strings.Repeat("f", maxSaltScratch+1),
	"caf\xc3\xa9 \xff not UTF-8",
}

// A salted value is a released format: operators compare what sys/audit-hash
// returns with what their log holds, across versions. The published test
// vector pins the algorithm; the rest pins that a pooled hash salts as a new
// one does, whatever it salted before.
func TestHMACer_SaltsAsANewHashDoes(t *testing.T) {
	ctx := context.Background()

	// RFC 4231, test case 2.
	got, err := NewHMACer("Jefe").Salt(ctx, "what do ya want for nothing?")
	if want := "hmac-sha256:5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"; err != nil || got != want {
		t.Fatalf("the RFC 4231 vector: got %q, %v; want %q", got, err, want)
	}

	const key = "0123456789abcdef0123456789abcdef"
	h := NewHMACer(key)
	// Twice over the values, and back: each use follows a different value.
	backwards := slices.Clone(saltValues)
	slices.Reverse(backwards)
	for _, value := range slices.Concat(saltValues, saltValues, backwards) {
		want := saltedWithNewHash(key, value)
		if got, err := h.Salt(ctx, value); err != nil || got != want {
			t.Fatalf("Salt of a %d-byte value: got %q, %v; want %q", len(value), got, err, want)
		}
		if got := string(h.AppendSalt([]byte("kept:"), value)); got != "kept:"+want {
			t.Fatalf("AppendSalt of a %d-byte value: got %q, want %q after what was there", len(value), got, want)
		}
	}

	if got := h.AppendSalt([]byte("kept:"), ""); string(got) != "kept:" {
		t.Errorf("AppendSalt of an empty value: got %q, want nothing appended", got)
	}
}

// Each HMACer salts under its own key, however their uses interleave: a
// hash keyed for one device never salts for another.
func TestHMACer_KeysDoNotMix(t *testing.T) {
	ctx := context.Background()
	first, second := NewHMACer("first-key"), NewHMACer("second-key")
	for range 3 {
		for _, value := range saltValues {
			if got, _ := first.Salt(ctx, value); got != saltedWithNewHash("first-key", value) {
				t.Fatalf("the first key salted a %d-byte value as %q", len(value), got)
			}
			if got, _ := second.Salt(ctx, value); got != saltedWithNewHash("second-key", value) {
				t.Fatalf("the second key salted a %d-byte value as %q", len(value), got)
			}
		}
	}
}

// Requests salt at the same time, under the same key.
func TestHMACer_Concurrent(t *testing.T) {
	const key = "shared-key"
	h := NewHMACer(key)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var dst []byte
			for n := range 500 {
				value := fmt.Sprintf("goroutine %d, value %d, %s", g, n, saltValues[n%len(saltValues)])
				dst = h.AppendSalt(dst[:0], value)
				if want := saltedWithNewHash(key, value); string(dst) != want {
					t.Errorf("got %q, want %q", dst, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// An HMACer made without NewHMACer salts, under an empty key, as it did
// before it kept its hashes.
func TestHMACer_ZeroValue(t *testing.T) {
	var h HMACer
	got, err := h.Salt(context.Background(), "value")
	if want := saltedWithNewHash("", "value"); err != nil || got != want {
		t.Errorf("got %q, %v; want %q", got, err, want)
	}
}

// Salting a value allocates nothing once its hash is keyed; returning it as
// a string allocates the string.
func TestHMACer_Allocations(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	h := NewHMACer("0123456789abcdef0123456789abcdef")
	const value = "ghs_16C7e42F292c6912E7710c838347Ae178B4a"
	dst := make([]byte, 0, saltedLen)

	if got := testing.AllocsPerRun(200, func() { dst = h.AppendSalt(dst[:0], value) }); got != 0 {
		t.Errorf("AppendSalt: %v allocations per value, want none", got)
	}
	if got := testing.AllocsPerRun(200, func() { h.Salt(context.Background(), value) }); got != 1 {
		t.Errorf("Salt: %v allocations per value, want the string alone", got)
	}
}

func BenchmarkHMACer(b *testing.B) {
	h := NewHMACer("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	const value = "ghs_16C7e42F292c6912E7710c838347Ae178B4a"

	// What a value cost when each had a hash keyed for it.
	b.Run("new-hash-per-value", func(b *testing.B) {
		const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			saltedWithNewHash(key, value)
		}
	})
	b.Run("Salt", func(b *testing.B) {
		ctx := context.Background()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			h.Salt(ctx, value)
		}
	})
	b.Run("AppendSalt", func(b *testing.B) {
		dst := make([]byte, 0, saltedLen)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			dst = h.AppendSalt(dst[:0], value)
		}
	})
	b.Run("AppendSalt-parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			dst := make([]byte, 0, saltedLen)
			for pb.Next() {
				dst = h.AppendSalt(dst[:0], value)
			}
		})
	})
}
