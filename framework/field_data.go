// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package framework

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
)

// FieldData is the structure passed to the callback to handle a path
// containing the populated parameters for fields. This should be used
// instead of the raw (*Request).Data to access data in a type-safe way.
type FieldData struct {
	Raw    map[string]interface{}
	Schema map[string]*FieldSchema
}

// Validate cycles through raw data and validates conversions in
// the schema, so we don't get an error/panic later when
// trying to get data out. Data not in the schema is not
// an error at this point, so we don't worry about it.
func (d *FieldData) Validate() error {
	for field := range d.Raw {
		schema, ok := d.Schema[field]
		if !ok {
			continue
		}

		switch schema.Type {
		case TypeBool, TypeInt, TypeInt64, TypeMap, TypeDurationSecond, TypeSignedDurationSecond, TypeString,
			TypeLowerCaseString, TypeNameString, TypeSlice, TypeStringSlice, TypeCommaStringSlice,
			TypeKVPairs, TypeCommaIntSlice, TypeHeader, TypeFloat, TypeTime:
			_, _, err := d.getPrimitive(field, schema)
			if err != nil {
				return fmt.Errorf("error converting input for field %q: %w", field, err)
			}
		default:
			return fmt.Errorf("unknown field type %q for field %q", schema.Type, field)
		}
	}

	return nil
}

// ValidateStrict cycles through raw data and validates conversions in the
// schema. In addition to the checks done by Validate, this function ensures
// that the raw data has all of the schema's required fields and does not
// have any fields outside of the schema.
func (d *FieldData) ValidateStrict() error {
	if d.Schema == nil {
		return nil
	}

	for field := range d.Raw {
		if _, _, err := d.GetOkErr(field); err != nil {
			return fmt.Errorf("field %q: %w", field, err)
		}
	}

	for field, schema := range d.Schema {
		if !schema.Required {
			continue
		}
		if _, ok := d.Raw[field]; !ok {
			return fmt.Errorf("missing required field %q", field)
		}
	}

	return nil
}

// Get gets the value for the given field. If the key is an invalid field,
// FieldData will panic. If you want a safer version of this method, use
// GetOk. If the field k is not set, the default value (if set) will be
// returned, otherwise the zero value will be returned.
func (d *FieldData) Get(k string) interface{} {
	schema, ok := d.Schema[k]
	if !ok {
		panic(fmt.Sprintf("field %s not in the schema", k))
	}

	value, ok := d.GetOk(k)
	if !ok || value == nil {
		value = schema.DefaultOrZero()
	}

	return value
}

// GetDefaultOrZero gets the default value set on the schema for the given
// field. If there is no default value set, the zero value of the type
// will be returned.
func (d *FieldData) GetDefaultOrZero(k string) interface{} {
	schema, ok := d.Schema[k]
	if !ok {
		panic(fmt.Sprintf("field %s not in the schema", k))
	}

	return schema.DefaultOrZero()
}

// GetFirst gets the value for the given field names, in order from first
// to last. This can be useful for fields with a current name, and one or
// more deprecated names.
func (d *FieldData) GetFirst(k ...string) (interface{}, bool) {
	for _, v := range k {
		if result, ok := d.GetOk(v); ok {
			return result, ok
		}
	}
	return nil, false
}

// GetOk gets the value for the given field. The second return value will be
// false if the key is invalid or the key is not set at all.
func (d *FieldData) GetOk(k string) (interface{}, bool) {
	schema, ok := d.Schema[k]
	if !ok {
		return nil, false
	}

	result, ok, err := d.GetOkErr(k)
	if err != nil {
		panic(fmt.Sprintf("error reading %s: %s", k, err))
	}

	if ok && result == nil {
		result = schema.DefaultOrZero()
	}

	return result, ok
}

// GetOkErr is the most conservative of all the Get methods. It returns
// whether key is set or not, but also an error value.
func (d *FieldData) GetOkErr(k string) (interface{}, bool, error) {
	schema, ok := d.Schema[k]
	if !ok {
		return nil, false, fmt.Errorf("unknown field: %q", k)
	}

	switch schema.Type {
	case TypeBool, TypeInt, TypeInt64, TypeMap, TypeDurationSecond, TypeSignedDurationSecond, TypeString,
		TypeLowerCaseString, TypeNameString, TypeSlice, TypeStringSlice, TypeCommaStringSlice,
		TypeKVPairs, TypeCommaIntSlice, TypeHeader, TypeFloat, TypeTime:
		return d.getPrimitive(k, schema)
	default:
		return nil, false,
			fmt.Errorf("unknown field type %q for field %q", schema.Type, k)
	}
}

func (d *FieldData) getPrimitive(k string, schema *FieldSchema) (interface{}, bool, error) {
	raw, ok := d.Raw[k]
	if !ok {
		return nil, false, nil
	}

	switch t := schema.Type; t {
	case TypeBool:
		var result bool
		if err := mapstructure.WeakDecode(raw, &result); err != nil {
			return nil, false, err
		}
		return result, true, nil

	case TypeInt:
		var result int
		if err := mapstructure.WeakDecode(raw, &result); err != nil {
			return nil, false, err
		}
		return result, true, nil

	case TypeInt64:
		var result int64
		if err := mapstructure.WeakDecode(raw, &result); err != nil {
			return nil, false, err
		}
		return result, true, nil

	case TypeFloat:
		var result float64
		if err := mapstructure.WeakDecode(raw, &result); err != nil {
			return nil, false, err
		}
		return result, true, nil

	case TypeString:
		var result string
		if err := mapstructure.WeakDecode(raw, &result); err != nil {
			return nil, false, err
		}
		return result, true, nil

	case TypeLowerCaseString:
		var result string
		if err := mapstructure.WeakDecode(raw, &result); err != nil {
			return nil, false, err
		}
		return strings.ToLower(result), true, nil

	case TypeNameString:
		var result string
		if err := mapstructure.WeakDecode(raw, &result); err != nil {
			return nil, false, err
		}
		matched, err := regexp.MatchString("^\\w(([\\w-.]+)?\\w)?$", result)
		if err != nil {
			return nil, false, err
		}
		if !matched {
			return nil, false, errors.New("field does not match the formatting rules")
		}
		return result, true, nil

	case TypeMap:
		var result map[string]interface{}
		if err := mapstructure.WeakDecode(raw, &result); err != nil {
			return nil, false, err
		}
		return result, true, nil

	case TypeDurationSecond, TypeSignedDurationSecond:
		var result int
		switch inp := raw.(type) {
		case nil:
			return nil, false, nil
		default:
			dur, err := parseutil.ParseDurationSecond(inp)
			if err != nil {
				return nil, false, err
			}
			result = int(dur.Seconds())
		}
		if t == TypeDurationSecond && result < 0 {
			return nil, false, fmt.Errorf("cannot provide negative value '%d'", result)
		}
		return result, true, nil

	case TypeTime:
		switch inp := raw.(type) {
		case nil:
			return nil, false, nil
		default:
			t, err := parseutil.ParseAbsoluteTime(inp)
			if err != nil {
				return nil, false, err
			}
			return t.UTC(), true, nil
		}

	case TypeCommaIntSlice:
		var result []int

		jsonIn, ok := raw.(json.Number)
		if ok {
			raw = jsonIn.String()
		}

		config := &mapstructure.DecoderConfig{
			Result:           &result,
			WeaklyTypedInput: true,
			DecodeHook:       mapstructure.StringToWeakSliceHookFunc(","),
		}
		decoder, err := mapstructure.NewDecoder(config)
		if err != nil {
			return nil, false, err
		}
		if err := decoder.Decode(raw); err != nil {
			return nil, false, err
		}
		if len(result) == 0 {
			return make([]int, 0), true, nil
		}
		return result, true, nil

	case TypeSlice:
		var result []interface{}
		if err := mapstructure.WeakDecode(raw, &result); err != nil {
			return nil, false, err
		}
		if len(result) == 0 {
			return make([]interface{}, 0), true, nil
		}
		return result, true, nil

	case TypeStringSlice:
		rawString, ok := raw.(string)
		if ok && rawString == "" {
			return []string{}, true, nil
		}

		var result []string
		if err := mapstructure.WeakDecode(raw, &result); err != nil {
			return nil, false, err
		}
		if len(result) == 0 {
			return make([]string, 0), true, nil
		}
		return strutil.TrimStrings(result), true, nil

	case TypeCommaStringSlice:
		res, err := parseutil.ParseCommaStringSlice(raw)
		if err != nil {
			return nil, false, err
		}
		return res, true, nil

	case TypeKVPairs:
		var mapResult map[string]string
		if err := mapstructure.WeakDecode(raw, &mapResult); err == nil {
			return mapResult, true, nil
		}

		var listResult []string
		if err := mapstructure.WeakDecode(raw, &listResult); err != nil {
			return nil, false, err
		}

		result := make(map[string]string, len(listResult))
		for _, keyPair := range listResult {
			keyPairSlice := strings.SplitN(keyPair, "=", 2)
			if len(keyPairSlice) != 2 || keyPairSlice[0] == "" {
				return nil, false, fmt.Errorf("invalid key pair %q", keyPair)
			}
			result[keyPairSlice[0]] = keyPairSlice[1]
		}
		return result, true, nil

	case TypeHeader:
		result := http.Header{}

		toHeader := func(resultMap map[string]interface{}) (http.Header, error) {
			header := http.Header{}
			for headerKey, headerValGroup := range resultMap {
				switch typedHeader := headerValGroup.(type) {
				case string:
					header.Add(headerKey, typedHeader)
				case []string:
					for _, headerVal := range typedHeader {
						header.Add(headerKey, headerVal)
					}
				case json.Number:
					header.Add(headerKey, typedHeader.String())
				case []interface{}:
					for _, headerVal := range typedHeader {
						switch typedHeader := headerVal.(type) {
						case string:
							header.Add(headerKey, typedHeader)
						case json.Number:
							header.Add(headerKey, typedHeader.String())
						default:
							return nil, fmt.Errorf("received non-string value for header key:%s, val:%s", headerKey, headerValGroup)
						}
					}
				default:
					return nil, fmt.Errorf("unrecognized type for %s", headerValGroup)
				}
			}
			return header, nil
		}

		resultMap := make(map[string]interface{})

		// 1. Are we getting a map from the API?
		if err := mapstructure.WeakDecode(raw, &resultMap); err == nil {
			result, err = toHeader(resultMap)
			if err != nil {
				return nil, false, err
			}
			return result, true, nil
		}

		// 2. Are we getting a JSON string?
		if headerStr, ok := raw.(string); ok {
			headerBytes, err := base64.StdEncoding.DecodeString(headerStr)
			if err != nil {
				headerBytes = []byte(headerStr)
			}
			if err := jsonutil.DecodeJSON(headerBytes, &resultMap); err != nil {
				return nil, false, err
			}
			result, err = toHeader(resultMap)
			if err != nil {
				return nil, false, err
			}
			return result, true, nil
		}

		// 3. Are we getting an array of fields like "content-type:encoding/json"?
		var keyPairs []interface{}
		if err := mapstructure.WeakDecode(raw, &keyPairs); err == nil {
			for _, keyPairIfc := range keyPairs {
				keyPair, ok := keyPairIfc.(string)
				if !ok {
					return nil, false, fmt.Errorf("invalid key pair %q", keyPair)
				}
				keyPairSlice := strings.SplitN(keyPair, ":", 2)
				if len(keyPairSlice) != 2 || keyPairSlice[0] == "" {
					return nil, false, fmt.Errorf("invalid key pair %q", keyPair)
				}
				result.Add(keyPairSlice[0], keyPairSlice[1])
			}
			return result, true, nil
		}
		return nil, false, fmt.Errorf("%s not provided an expected format", raw)

	default:
		panic(fmt.Sprintf("Unknown type: %s", schema.Type))
	}
}

func (d *FieldData) GetWithExplicitDefault(field string, defaultValue interface{}) interface{} {
	assignedValue, ok := d.GetOk(field)
	if ok {
		return assignedValue
	}
	return defaultValue
}

func (d *FieldData) GetTimeWithExplicitDefault(field string, defaultValue time.Duration) time.Duration {
	assignedValue, ok := d.GetOk(field)
	if ok {
		return time.Duration(assignedValue.(int)) * time.Second
	}
	return defaultValue
}
