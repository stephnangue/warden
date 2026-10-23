package helper

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/mitchellh/pointerstructure"
)

// GetClaim resolves a claim value. A leading "/" is interpreted as a JSON
// Pointer (RFC 6901) so nested claims can be addressed (e.g.
// "/resource_access/warden/env"); any other string is a literal top-level key,
// which also makes namespaced OIDC keys like "https://warden.io/env" resolve
// as-is. Returns nil when the claim is absent or the pointer cannot be walked
// (fail closed). A float is truncated to an integer and returned as a
// json.Number, so numeric claims stringify predictably.
func GetClaim(claims map[string]interface{}, claim string) interface{} {
	var val interface{}
	if !strings.HasPrefix(claim, "/") {
		val = claims[claim]
	} else {
		v, err := pointerstructure.Get(claims, claim)
		if err != nil {
			return nil
		}
		val = v
	}

	switch v := val.(type) {
	case float32:
		return json.Number(strconv.Itoa(int(v)))
	case float64:
		return json.Number(strconv.Itoa(int(v)))
	}
	return val
}
