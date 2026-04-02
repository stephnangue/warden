package framework

import (
	"context"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenericNameRegex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		match bool
	}{
		{"simple", "foo", true},
		{"with-dash", "foo-bar", true},
		{"with-dot", "foo.bar", true},
		{"with-underscore", "foo_bar", true},
		{"starts-with-letter", "a", true},
		{"empty", "", false},
		{"starts-with-dash", "-foo", false},
		{"ends-with-dash", "foo-", false},
		{"with-slash", "foo/bar", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{
				Paths: []*Path{{
					Pattern: "items/" + GenericNameRegex("name"),
				}},
			}
			p := b.Route("items/" + tc.input)
			if tc.match {
				assert.NotNil(t, p, "expected match for %q", tc.input)
			} else {
				assert.Nil(t, p, "expected no match for %q", tc.input)
			}
		})
	}
}

func TestOptionalGenericNameRegex(t *testing.T) {
	b := &Backend{
		Paths: []*Path{{
			Pattern: "items" + OptionalGenericNameRegex("name"),
		}},
	}

	t.Run("without name", func(t *testing.T) {
		p := b.Route("items")
		assert.NotNil(t, p)
	})

	t.Run("with name", func(t *testing.T) {
		p := b.Route("items/foo")
		assert.NotNil(t, p)
	})
}

func TestGenericNameWithAtRegex(t *testing.T) {
	b := &Backend{
		Paths: []*Path{{
			Pattern: "users/" + GenericNameWithAtRegex("email"),
		}},
	}

	p := b.Route("users/user@example.com")
	assert.NotNil(t, p)
}

func TestOptionalParamRegex(t *testing.T) {
	b := &Backend{
		Paths: []*Path{{
			Pattern: "path" + OptionalParamRegex("rest"),
		}},
	}

	t.Run("without param", func(t *testing.T) {
		assert.NotNil(t, b.Route("path"))
	})

	t.Run("with param", func(t *testing.T) {
		assert.NotNil(t, b.Route("path/a/b/c"))
	})
}

func TestMatchAllRegex(t *testing.T) {
	b := &Backend{
		Paths: []*Path{{
			Pattern: "gateway/" + MatchAllRegex("path"),
		}},
	}

	assert.NotNil(t, b.Route("gateway/v1/messages"))
	assert.NotNil(t, b.Route("gateway/"))
	assert.NotNil(t, b.Route("gateway/a/b/c/d"))
}

func TestPathAppend(t *testing.T) {
	p1 := []*Path{{Pattern: "a"}}
	p2 := []*Path{{Pattern: "b"}, {Pattern: "c"}}
	result := PathAppend(p1, p2)
	require.Len(t, result, 3)
	assert.Equal(t, "a", result[0].Pattern)
	assert.Equal(t, "c", result[2].Pattern)
}

func TestPathAppend_Empty(t *testing.T) {
	result := PathAppend()
	assert.Empty(t, result)
}

func TestPathOperation_Properties(t *testing.T) {
	op := &PathOperation{
		Callback: func(_ context.Context, _ *logical.Request, _ *FieldData) (*logical.Response, error) {
			return nil, nil
		},
		Summary:     "  Test summary  ",
		Description: "  Test desc  ",
		Unpublished: true,
		Deprecated:  true,
	}

	assert.NotNil(t, op.Handler())

	props := op.Properties()
	assert.Equal(t, "Test summary", props.Summary)
	assert.Equal(t, "Test desc", props.Description)
	assert.True(t, props.Unpublished)
	assert.True(t, props.Deprecated)
}

func TestFieldSchema_DefaultOrZero(t *testing.T) {
	t.Run("with default", func(t *testing.T) {
		s := &FieldSchema{Type: TypeString, Default: "hello"}
		assert.Equal(t, "hello", s.DefaultOrZero())
	})

	t.Run("without default", func(t *testing.T) {
		s := &FieldSchema{Type: TypeString}
		assert.Equal(t, "", s.DefaultOrZero())
	})

	t.Run("int zero", func(t *testing.T) {
		s := &FieldSchema{Type: TypeInt}
		assert.Equal(t, 0, s.DefaultOrZero())
	})

	t.Run("bool zero", func(t *testing.T) {
		s := &FieldSchema{Type: TypeBool}
		assert.Equal(t, false, s.DefaultOrZero())
	})

	t.Run("duration with default string", func(t *testing.T) {
		s := &FieldSchema{Type: TypeDurationSecond, Default: "30s"}
		assert.Equal(t, 30, s.DefaultOrZero())
	})

	t.Run("duration with invalid default", func(t *testing.T) {
		s := &FieldSchema{Type: TypeDurationSecond, Default: "invalid"}
		assert.Equal(t, 0, s.DefaultOrZero())
	})
}

func TestFieldType_Zero(t *testing.T) {
	tests := []struct {
		ft       FieldType
		expected interface{}
	}{
		{TypeString, ""},
		{TypeNameString, ""},
		{TypeLowerCaseString, ""},
		{TypeInt, 0},
		{TypeInt64, int64(0)},
		{TypeBool, false},
		{TypeFloat, 0.0},
		{TypeDurationSecond, 0},
		{TypeSignedDurationSecond, 0},
	}

	for _, tc := range tests {
		t.Run(tc.ft.String(), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.ft.Zero())
		})
	}
}

func TestFieldType_Zero_Collections(t *testing.T) {
	assert.NotNil(t, TypeMap.Zero())
	assert.NotNil(t, TypeKVPairs.Zero())
	assert.NotNil(t, TypeSlice.Zero())
	assert.NotNil(t, TypeStringSlice.Zero())
	assert.NotNil(t, TypeCommaStringSlice.Zero())
	assert.NotNil(t, TypeCommaIntSlice.Zero())
	assert.NotNil(t, TypeHeader.Zero())
	assert.NotNil(t, TypeTime.Zero())
}
