package helper

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// AuthRolesRemovedMessage answers every request under an auth mount's role/
// path: auth roles were removed, and roles now live in the namespace.
const AuthRolesRemovedMessage = "auth roles were removed; define roles with sys/roles/<name> and grant them " +
	"with groups (warden role create, warden identity group create)"

// RolePrefix is the storage prefix, relative to an auth mount, under which
// auth roles were kept. Nothing reads or writes it any more; core lists it at
// unseal only to warn that it is left over.
const RolePrefix = "role/"

// RemovedRolePaths returns the paths an auth method keeps where its roles
// were: every operation on role/ and on anything below it answers 410 Gone
// with AuthRolesRemovedMessage, so a client still managing auth roles learns
// where they went rather than reading a 404. The handler touches no storage.
func RemovedRolePaths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         "role/?$",
			Operations:      removedRoleOperations(),
			HelpSynopsis:    "Removed: auth roles",
			HelpDescription: AuthRolesRemovedMessage,
		},
		{
			Pattern: "role/" + framework.MatchAllRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {Type: framework.TypeString, Description: "Name of the removed auth role"},
			},
			Operations:      removedRoleOperations(),
			HelpSynopsis:    "Removed: auth roles",
			HelpDescription: AuthRolesRemovedMessage,
		},
	}
}

func removedRoleOperations() map[logical.Operation]framework.OperationHandler {
	ops := make(map[logical.Operation]framework.OperationHandler, 6)
	for _, op := range []logical.Operation{
		logical.CreateOperation, logical.ReadOperation, logical.UpdateOperation,
		logical.PatchOperation, logical.DeleteOperation, logical.ListOperation,
	} {
		ops[op] = &framework.PathOperation{Callback: handleRoleRemoved, Summary: "Removed: answers 410 Gone"}
	}
	return ops
}

func handleRoleRemoved(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
	return logical.ErrorResponse(logical.ErrGone(AuthRolesRemovedMessage)), nil
}

// removedConfigKeys are the auth mount configuration keys of the role era,
// each with what replaced it. A stored config that still carries one is loaded
// without it (RemovedConfigKeys, RemovedConfigWarnings); a config write or a
// mount enable that carries one is refused (RefuseRemovedConfigKeys).
var removedConfigKeys = map[string]string{
	"default_role":        "set default_role on the provider instead, where it names a namespace role",
	"groups_claim":        "grant roles with groups (warden identity group create)",
	"group_policy_prefix": "grant roles with groups (warden identity group create)",
	"metadata_claims":     "metadata_claims was replaced by facts",
	"metadata_mappings":   "metadata_mappings was replaced by facts",
	"token_type":          "the token type follows from the auth method",
}

// RemovedConfigKeys returns, sorted, the removed configuration keys conf sets
// to a value (an empty string, map or list sets nothing), or nil.
func RemovedConfigKeys(conf map[string]any) []string {
	var out []string
	for key := range removedConfigKeys {
		if v, ok := conf[key]; ok && isSet(v) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// RemovedConfigWarnings returns one config-read warning per key in keys (as
// RemovedConfigKeys returns them), or nil.
func RemovedConfigWarnings(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, len(keys))
	for i, key := range keys {
		out[i] = fmt.Sprintf("%s was removed and is ignored: %s; any config write removes it", key, removedConfigKeys[key])
	}
	return out
}

// SetWarnings puts warnings under data["warnings"] when there are any. A
// config read's warnings reach an HTTP client only in the response data: a
// response's Warnings field is not serialized.
func SetWarnings(data map[string]any, warnings []string) {
	if len(warnings) > 0 {
		data["warnings"] = warnings
	}
}

// reservedConfigKeys are auth mount configuration keys kept for what is to
// come, each with what it will mean, so no method gives one another meaning
// first. A config write or a mount enable that sets one is refused.
var reservedConfigKeys = map[string]string{
	"agent_claim": "it will name the claim that selects one agent among several presenting one native identity",
}

// RefuseRemovedConfigKeys refuses, with a 400 naming each key and what
// replaced it, a configuration that sets a removed key, or a reserved one.
// raw is the write's request data, or a mount's config when it is enabled.
func RefuseRemovedConfigKeys(raw map[string]any) error {
	var parts []string
	for _, key := range RemovedConfigKeys(raw) {
		parts = append(parts, key+" was removed: "+removedConfigKeys[key])
	}
	for _, key := range slices.Sorted(maps.Keys(reservedConfigKeys)) {
		if v, ok := raw[key]; ok && isSet(v) {
			parts = append(parts, key+" is reserved: "+reservedConfigKeys[key])
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return logical.ErrBadRequest(strings.Join(parts, "; "))
}

// isSet reports whether v sets a value: anything but nil, or an empty string,
// map, slice or array.
func isSet(v any) bool {
	if v == nil {
		return false
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.String, reflect.Map, reflect.Slice, reflect.Array:
		return rv.Len() > 0
	}
	return true
}
