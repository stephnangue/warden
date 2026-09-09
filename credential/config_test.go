package credential

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_ZeroValueIsUsableAndEmpty(t *testing.T) {
	var c Config

	assert.Equal(t, 0, c.Len())
	assert.Equal(t, "", c.Get("anything"))
	_, ok := c.Lookup("anything")
	assert.False(t, ok)
	assert.Empty(t, c.Map())
	assert.True(t, c.Equal(Config{}))

	for range c.All() {
		t.Fatal("the zero value must iterate nothing")
	}

	// And it is still a usable base for a derived config.
	assert.Equal(t, "v", c.With("k", "v").Get("k"))
}

// TestConfig_NewConfigCopiesInput is the point of the type: a caller cannot keep a
// handle on the map it handed over and write through it afterwards. Without the
// copy, "do not retain the map you passed" would be one more convention of exactly
// the kind this type exists to remove.
func TestConfig_NewConfigCopiesInput(t *testing.T) {
	raw := map[string]string{"region": "us-east-1"}
	cfg := NewConfig(raw)

	raw["region"] = "eu-west-1"
	raw["injected"] = "yes"

	assert.Equal(t, "us-east-1", cfg.Get("region"), "later writes to the source map must not be visible")
	_, present := cfg.Lookup("injected")
	assert.False(t, present, "keys added after construction must not appear")
}

// TestConfig_MapReturnsACopy is the same guarantee on the way out: the boundary
// escape hatch must not hand back a handle on the live map.
func TestConfig_MapReturnsACopy(t *testing.T) {
	cfg := NewConfig(map[string]string{"region": "us-east-1"})

	out := cfg.Map()
	out["region"] = "eu-west-1"
	delete(out, "region")
	out["injected"] = "yes"

	assert.Equal(t, "us-east-1", cfg.Get("region"))
	_, present := cfg.Lookup("injected")
	assert.False(t, present)
}

func TestConfig_LookupDistinguishesEmptyFromAbsent(t *testing.T) {
	cfg := NewConfig(map[string]string{"set_but_empty": ""})

	v, ok := cfg.Lookup("set_but_empty")
	assert.True(t, ok, "a stored empty string is present")
	assert.Equal(t, "", v)

	_, ok = cfg.Lookup("absent")
	assert.False(t, ok)

	// Get cannot tell them apart, which is why several validators need Lookup.
	assert.Equal(t, cfg.Get("set_but_empty"), cfg.Get("absent"))
}

func TestConfig_WithDoesNotTouchTheReceiver(t *testing.T) {
	base := NewConfig(map[string]string{"a": "1"})

	derived := base.With("b", "2")
	overridden := base.With("a", "9")

	assert.Equal(t, 1, base.Len(), "the receiver is unchanged")
	assert.Equal(t, "1", base.Get("a"))

	assert.Equal(t, "1", derived.Get("a"))
	assert.Equal(t, "2", derived.Get("b"))

	assert.Equal(t, "9", overridden.Get("a"))
	assert.Equal(t, "1", base.Get("a"), "overriding a key must not reach back")
}

func TestConfig_WithAllAppliesOverrides(t *testing.T) {
	base := NewConfig(map[string]string{"a": "1", "b": "2"})

	overrides := map[string]string{"b": "changed", "c": "new"}
	derived := base.WithAll(overrides)

	assert.Equal(t, "1", derived.Get("a"))
	assert.Equal(t, "changed", derived.Get("b"))
	assert.Equal(t, "new", derived.Get("c"))

	assert.Equal(t, "2", base.Get("b"), "the receiver is unchanged")

	// The overrides map is not retained either.
	overrides["c"] = "mutated"
	assert.Equal(t, "new", derived.Get("c"))
}

func TestConfig_Without(t *testing.T) {
	base := NewConfig(map[string]string{"a": "1", "b": "2", "c": "3"})

	derived := base.Without("b", "missing")

	assert.Equal(t, 2, derived.Len())
	_, present := derived.Lookup("b")
	assert.False(t, present)
	assert.Equal(t, 3, base.Len(), "the receiver is unchanged")
}

func TestConfig_Equal(t *testing.T) {
	a := NewConfig(map[string]string{"x": "1", "y": "2"})
	b := NewConfig(map[string]string{"y": "2", "x": "1"})
	c := NewConfig(map[string]string{"x": "1"})

	assert.True(t, a.Equal(b), "order is irrelevant")
	assert.False(t, a.Equal(c))
	assert.True(t, Config{}.Equal(NewConfig(nil)))
	assert.True(t, NewConfig(map[string]string{}).Equal(Config{}))
}

func TestConfig_All(t *testing.T) {
	cfg := NewConfig(map[string]string{"a": "1", "b": "2"})

	got := map[string]string{}
	for k, v := range cfg.All() {
		got[k] = v
	}
	assert.True(t, maps.Equal(map[string]string{"a": "1", "b": "2"}, got))

	// Callers get break for free, which is why All beats a Range callback.
	var seen int
	for range cfg.All() {
		seen++
		break
	}
	assert.Equal(t, 1, seen)
}

func TestConfig_Prefixed(t *testing.T) {
	cfg := NewConfig(map[string]string{
		"token_param.resource": "https://api.example.com",
		"token_param.scope":    "read",
		"unrelated":            "x",
	})

	got := cfg.Prefixed("token_param.")

	require.Len(t, got, 2)
	assert.Equal(t, "https://api.example.com", got["resource"])
	assert.Equal(t, "read", got["scope"])
	assert.NotContains(t, got, "unrelated")
}
