package framework

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldData_Get(t *testing.T) {
	d := &FieldData{
		Raw: map[string]interface{}{"name": "hello", "count": 42},
		Schema: map[string]*FieldSchema{
			"name":  {Type: TypeString},
			"count": {Type: TypeInt, Default: 10},
		},
	}

	t.Run("existing field", func(t *testing.T) {
		assert.Equal(t, "hello", d.Get("name"))
	})

	t.Run("returns default when not set", func(t *testing.T) {
		d2 := &FieldData{
			Raw: map[string]interface{}{},
			Schema: map[string]*FieldSchema{
				"count": {Type: TypeInt, Default: 10},
			},
		}
		assert.Equal(t, 10, d2.Get("count"))
	})

	t.Run("panics on unknown field", func(t *testing.T) {
		assert.Panics(t, func() { d.Get("unknown") })
	})
}

func TestFieldData_GetOk(t *testing.T) {
	d := &FieldData{
		Raw: map[string]interface{}{"name": "hello"},
		Schema: map[string]*FieldSchema{
			"name": {Type: TypeString},
			"age":  {Type: TypeInt},
		},
	}

	t.Run("set field", func(t *testing.T) {
		v, ok := d.GetOk("name")
		assert.True(t, ok)
		assert.Equal(t, "hello", v)
	})

	t.Run("unset field", func(t *testing.T) {
		_, ok := d.GetOk("age")
		assert.False(t, ok)
	})

	t.Run("unknown field", func(t *testing.T) {
		_, ok := d.GetOk("nope")
		assert.False(t, ok)
	})
}

func TestFieldData_GetOkErr(t *testing.T) {
	d := &FieldData{
		Raw: map[string]interface{}{"name": "hello"},
		Schema: map[string]*FieldSchema{
			"name": {Type: TypeString},
		},
	}

	t.Run("known field", func(t *testing.T) {
		v, ok, err := d.GetOkErr("name")
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "hello", v)
	})

	t.Run("unknown field", func(t *testing.T) {
		_, _, err := d.GetOkErr("unknown")
		assert.Error(t, err)
	})
}

func TestFieldData_GetFirst(t *testing.T) {
	d := &FieldData{
		Raw: map[string]interface{}{"new_name": "val"},
		Schema: map[string]*FieldSchema{
			"new_name": {Type: TypeString},
			"old_name": {Type: TypeString},
		},
	}

	v, ok := d.GetFirst("old_name", "new_name")
	assert.True(t, ok)
	assert.Equal(t, "val", v)

	_, ok = d.GetFirst("missing1", "missing2")
	assert.False(t, ok)
}

func TestFieldData_GetDefaultOrZero(t *testing.T) {
	d := &FieldData{
		Schema: map[string]*FieldSchema{
			"with_default": {Type: TypeString, Default: "def"},
			"no_default":   {Type: TypeInt},
		},
	}

	assert.Equal(t, "def", d.GetDefaultOrZero("with_default"))
	assert.Equal(t, 0, d.GetDefaultOrZero("no_default"))
}

func TestFieldData_GetWithExplicitDefault(t *testing.T) {
	d := &FieldData{
		Raw: map[string]interface{}{"set": "val"},
		Schema: map[string]*FieldSchema{
			"set":   {Type: TypeString},
			"unset": {Type: TypeString},
		},
	}

	assert.Equal(t, "val", d.GetWithExplicitDefault("set", "fallback"))
	assert.Equal(t, "fallback", d.GetWithExplicitDefault("unset", "fallback"))
}

func TestFieldData_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		d := &FieldData{
			Raw:    map[string]interface{}{"name": "hello", "count": 42},
			Schema: map[string]*FieldSchema{"name": {Type: TypeString}, "count": {Type: TypeInt}},
		}
		assert.NoError(t, d.Validate())
	})

	t.Run("invalid type conversion", func(t *testing.T) {
		d := &FieldData{
			Raw:    map[string]interface{}{"count": "not-a-number"},
			Schema: map[string]*FieldSchema{"count": {Type: TypeInt}},
		}
		// mapstructure.WeakDecode may or may not error — depends on input
		// "not-a-number" will fail WeakDecode to int
		err := d.Validate()
		assert.Error(t, err)
	})

	t.Run("extra fields ignored", func(t *testing.T) {
		d := &FieldData{
			Raw:    map[string]interface{}{"extra": "val"},
			Schema: map[string]*FieldSchema{"name": {Type: TypeString}},
		}
		assert.NoError(t, d.Validate())
	})
}

func TestFieldData_ValidateStrict(t *testing.T) {
	t.Run("nil schema", func(t *testing.T) {
		d := &FieldData{Raw: map[string]interface{}{"a": "b"}}
		assert.NoError(t, d.ValidateStrict())
	})

	t.Run("missing required", func(t *testing.T) {
		d := &FieldData{
			Raw:    map[string]interface{}{},
			Schema: map[string]*FieldSchema{"name": {Type: TypeString, Required: true}},
		}
		err := d.ValidateStrict()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing required")
	})

	t.Run("unknown field", func(t *testing.T) {
		d := &FieldData{
			Raw:    map[string]interface{}{"unknown": "val"},
			Schema: map[string]*FieldSchema{"name": {Type: TypeString}},
		}
		err := d.ValidateStrict()
		assert.Error(t, err)
	})

	t.Run("valid strict", func(t *testing.T) {
		d := &FieldData{
			Raw:    map[string]interface{}{"name": "hello"},
			Schema: map[string]*FieldSchema{"name": {Type: TypeString, Required: true}},
		}
		assert.NoError(t, d.ValidateStrict())
	})
}

func TestFieldData_TypeConversions(t *testing.T) {
	tests := []struct {
		name     string
		ft       FieldType
		raw      interface{}
		expected interface{}
	}{
		{"string", TypeString, "hello", "hello"},
		{"int", TypeInt, 42, 42},
		{"int from string", TypeInt, "42", 42},
		{"int64", TypeInt64, int64(100), int64(100)},
		{"bool true", TypeBool, true, true},
		{"bool from string", TypeBool, "true", true},
		{"float", TypeFloat, 3.14, 3.14},
		{"lowercase", TypeLowerCaseString, "HELLO", "hello"},
		{"duration", TypeDurationSecond, "30s", 30},
		{"duration int", TypeDurationSecond, 60, 60},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &FieldData{
				Raw:    map[string]interface{}{"field": tc.raw},
				Schema: map[string]*FieldSchema{"field": {Type: tc.ft}},
			}
			v, ok := d.GetOk("field")
			assert.True(t, ok)
			assert.Equal(t, tc.expected, v)
		})
	}
}

func TestFieldData_NameString(t *testing.T) {
	d := &FieldData{
		Schema: map[string]*FieldSchema{"name": {Type: TypeNameString}},
	}

	t.Run("valid name", func(t *testing.T) {
		d.Raw = map[string]interface{}{"name": "valid-name"}
		v, ok := d.GetOk("name")
		assert.True(t, ok)
		assert.Equal(t, "valid-name", v)
	})

	t.Run("invalid name", func(t *testing.T) {
		d.Raw = map[string]interface{}{"name": "invalid name with spaces"}
		assert.Panics(t, func() { d.GetOk("name") })
	})
}

func TestFieldData_StringSlice(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"items": []string{"a", "b", "c"}},
		Schema: map[string]*FieldSchema{"items": {Type: TypeStringSlice}},
	}
	v, ok := d.GetOk("items")
	assert.True(t, ok)
	assert.Equal(t, []string{"a", "b", "c"}, v)
}

func TestFieldData_CommaStringSlice(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"items": "a,b,c"},
		Schema: map[string]*FieldSchema{"items": {Type: TypeCommaStringSlice}},
	}
	v, ok := d.GetOk("items")
	assert.True(t, ok)
	assert.Equal(t, []string{"a", "b", "c"}, v)
}

func TestFieldData_Map(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"data": map[string]interface{}{"key": "val"}},
		Schema: map[string]*FieldSchema{"data": {Type: TypeMap}},
	}
	v, ok := d.GetOk("data")
	assert.True(t, ok)
	m := v.(map[string]interface{})
	assert.Equal(t, "val", m["key"])
}

func TestFieldData_KVPairs(t *testing.T) {
	t.Run("from map", func(t *testing.T) {
		d := &FieldData{
			Raw:    map[string]interface{}{"kv": map[string]string{"a": "1"}},
			Schema: map[string]*FieldSchema{"kv": {Type: TypeKVPairs}},
		}
		v, ok := d.GetOk("kv")
		assert.True(t, ok)
		assert.Equal(t, map[string]string{"a": "1"}, v)
	})

	t.Run("from list", func(t *testing.T) {
		d := &FieldData{
			Raw:    map[string]interface{}{"kv": []string{"a=1", "b=2"}},
			Schema: map[string]*FieldSchema{"kv": {Type: TypeKVPairs}},
		}
		v, ok := d.GetOk("kv")
		assert.True(t, ok)
		m := v.(map[string]string)
		assert.Equal(t, "1", m["a"])
		assert.Equal(t, "2", m["b"])
	})
}

func TestFieldData_DurationSecond_Negative(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"ttl": -10},
		Schema: map[string]*FieldSchema{"ttl": {Type: TypeDurationSecond}},
	}
	assert.Panics(t, func() { d.GetOk("ttl") })
}

func TestFieldData_SignedDurationSecond(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"ttl": -10},
		Schema: map[string]*FieldSchema{"ttl": {Type: TypeSignedDurationSecond}},
	}
	v, ok := d.GetOk("ttl")
	assert.True(t, ok)
	assert.Equal(t, -10, v)
}

func TestFieldData_GetTimeWithExplicitDefault(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"ttl": "30s"},
		Schema: map[string]*FieldSchema{"ttl": {Type: TypeDurationSecond}},
	}

	t.Run("set value", func(t *testing.T) {
		result := d.GetTimeWithExplicitDefault("ttl", 60*time.Second)
		assert.Equal(t, 30*time.Second, result)
	})

	t.Run("default value", func(t *testing.T) {
		d2 := &FieldData{
			Raw:    map[string]interface{}{},
			Schema: map[string]*FieldSchema{"ttl": {Type: TypeDurationSecond}},
		}
		result := d2.GetTimeWithExplicitDefault("ttl", 60*time.Second)
		assert.Equal(t, 60*time.Second, result)
	})
}

func TestFieldData_Header(t *testing.T) {
	t.Run("from map", func(t *testing.T) {
		d := &FieldData{
			Raw: map[string]interface{}{
				"headers": map[string]interface{}{
					"Content-Type": "application/json",
					"X-Custom":     []interface{}{"a", "b"},
				},
			},
			Schema: map[string]*FieldSchema{"headers": {Type: TypeHeader}},
		}
		v, ok := d.GetOk("headers")
		assert.True(t, ok)
		h := v.(http.Header)
		assert.Equal(t, "application/json", h.Get("Content-Type"))
		assert.Equal(t, []string{"a", "b"}, h.Values("X-Custom"))
	})
}

func TestFieldData_CommaIntSlice(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"ids": "1,2,3"},
		Schema: map[string]*FieldSchema{"ids": {Type: TypeCommaIntSlice}},
	}
	v, ok := d.GetOk("ids")
	assert.True(t, ok)
	assert.Equal(t, []int{1, 2, 3}, v)
}

func TestFieldData_Slice(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"items": []interface{}{"a", 1, true}},
		Schema: map[string]*FieldSchema{"items": {Type: TypeSlice}},
	}
	v, ok := d.GetOk("items")
	assert.True(t, ok)
	assert.Len(t, v.([]interface{}), 3)
}

func TestFieldData_EmptyStringSlice(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"items": ""},
		Schema: map[string]*FieldSchema{"items": {Type: TypeStringSlice}},
	}
	v, ok := d.GetOk("items")
	assert.True(t, ok)
	assert.Equal(t, []string{}, v)
}

func TestFieldData_DurationNil(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"ttl": nil},
		Schema: map[string]*FieldSchema{"ttl": {Type: TypeDurationSecond}},
	}
	v, ok, err := d.GetOkErr("ttl")
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, v)
}

func TestFieldData_Int64(t *testing.T) {
	d := &FieldData{
		Raw:    map[string]interface{}{"size": int64(42)},
		Schema: map[string]*FieldSchema{"size": {Type: TypeInt64}},
	}
	v, ok := d.GetOk("size")
	assert.True(t, ok)
	assert.Equal(t, int64(42), v)
}
