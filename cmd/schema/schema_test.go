package schema

import (
	"reflect"
	"sort"
	"testing"
)

func TestMethodsOf(t *testing.T) {
	tests := []struct {
		name string
		item map[string]any
		want []string
	}{
		{"none", map[string]any{}, []string{}},
		{"get only", map[string]any{"get": map[string]any{}}, []string{"GET"}},
		{
			"get + post + delete",
			map[string]any{"get": map[string]any{}, "post": map[string]any{}, "delete": map[string]any{}},
			[]string{"GET", "POST", "DELETE"},
		},
		{
			"all standard verbs in canonical order",
			map[string]any{"delete": map[string]any{}, "get": map[string]any{}, "post": map[string]any{}, "put": map[string]any{}, "patch": map[string]any{}},
			[]string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		},
		{"ignores unknown keys", map[string]any{"x-vault-sudo": true, "description": "x"}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := methodsOf(tt.item)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("methodsOf = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestProjectPath_AuthRequired(t *testing.T) {
	// Default: auth required (no x-vault-unauthenticated flag).
	out := projectPath("/sys/auth", map[string]any{
		"get": map[string]any{},
	}, nil)
	if out["auth_required"] != true {
		t.Errorf("auth_required = %v; want true", out["auth_required"])
	}
}

func TestProjectPath_Unauthenticated(t *testing.T) {
	// x-vault-unauthenticated=true should flip auth_required to false.
	out := projectPath("/sys/health", map[string]any{
		"x-vault-unauthenticated": true,
		"get":                     map[string]any{},
	}, nil)
	if out["auth_required"] != false {
		t.Errorf("auth_required = %v; want false", out["auth_required"])
	}
}

func TestProjectPath_Sudo(t *testing.T) {
	out := projectPath("/sys/init", map[string]any{
		"x-vault-sudo": true,
		"post":         map[string]any{},
	}, nil)
	if out["sudo_required"] != true {
		t.Errorf("sudo_required = %v; want true", out["sudo_required"])
	}
}

func TestProjectPath_DescriptionFromPathItem(t *testing.T) {
	// The framework generator wires HelpSynopsis into pathItem.description.
	out := projectPath("/aws/config", map[string]any{
		"description": "Configure the AWS provider's proxy domains and limits.",
		"get":         map[string]any{},
	}, nil)
	if out["description"] != "Configure the AWS provider's proxy domains and limits." {
		t.Errorf("description = %v; want path-item description", out["description"])
	}
}

func TestProjectPath_DescriptionFallsBackToOperation(t *testing.T) {
	// No path-item description; fall back to the first operation's summary.
	out := projectPath("/aws/config", map[string]any{
		"post": map[string]any{
			"summary": "Update the AWS configuration",
		},
	}, nil)
	if out["description"] != "Update the AWS configuration" {
		t.Errorf("description = %v; want operation summary fallback", out["description"])
	}
}

func TestProjectPath_DescriptionOmittedWhenEmpty(t *testing.T) {
	// No description anywhere → field is omitted, not set to "".
	out := projectPath("/aws/config", map[string]any{
		"get": map[string]any{},
	}, nil)
	if _, ok := out["description"]; ok {
		t.Errorf("description should be omitted when no help text exists; got %v", out["description"])
	}
}

func TestMergeParameters_PathParametersOnly(t *testing.T) {
	item := map[string]any{
		"parameters": []any{
			map[string]any{
				"name":     "name",
				"in":       "path",
				"required": true,
				"schema":   map[string]any{"type": "string"},
			},
		},
		"get": map[string]any{},
	}
	got := mergeParameters(item, nil)
	want := []map[string]any{
		{"name": "name", "in": "path", "required": true, "type": "string"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeParameters = %#v; want %#v", got, want)
	}
}

func TestMergeParameters_BodyFromRequestBody(t *testing.T) {
	item := map[string]any{
		"post": map[string]any{
			"requestBody": map[string]any{
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"description": map[string]any{
									"type":        "string",
									"description": "Human-friendly description",
								},
								"max_body_size": map[string]any{"type": "integer"},
							},
							"required": []any{"max_body_size"},
						},
					},
				},
			},
		},
	}
	got := mergeParameters(item, nil)
	// Body params come out alphabetically; we don't assume order from the map.
	sort.Slice(got, func(i, j int) bool { return got[i]["name"].(string) < got[j]["name"].(string) })
	want := []map[string]any{
		{"name": "description", "in": "body", "type": "string", "description": "Human-friendly description"},
		{"name": "max_body_size", "in": "body", "type": "integer", "required": true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeParameters body = %#v; want %#v", got, want)
	}
}

func TestMergeParameters_DeduplicatesAcrossOperations(t *testing.T) {
	// "name" appears as a path parameter at the path-item level AND inside
	// each operation's parameter list. Should appear in the result exactly
	// once (the first-seen wins, mirroring OpenAPI's shared-parameter
	// convention).
	item := map[string]any{
		"parameters": []any{
			map[string]any{"name": "name", "in": "path", "required": true},
		},
		"get":  map[string]any{"parameters": []any{map[string]any{"name": "name", "in": "path"}}},
		"post": map[string]any{"parameters": []any{map[string]any{"name": "name", "in": "path"}}},
	}
	got := mergeParameters(item, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 parameter (deduplicated), got %d: %#v", len(got), got)
	}
}

func TestMergeParameters_SensitiveFromDisplayAttrs(t *testing.T) {
	item := map[string]any{
		"post": map[string]any{
			"requestBody": map[string]any{
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"access_key": map[string]any{
									"type": "string",
									"x-vault-displayAttrs": map[string]any{
										"sensitive": true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	got := mergeParameters(item, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 parameter, got %d", len(got))
	}
	if got[0]["sensitive"] != true {
		t.Errorf("expected sensitive=true on access_key, got %#v", got[0])
	}
}

func TestSuccessResponseSchema_PrefersJSON(t *testing.T) {
	item := map[string]any{
		"get": map[string]any{
			"responses": map[string]any{
				"200": map[string]any{
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"name": map[string]any{"type": "string"},
								},
							},
						},
					},
				},
			},
		},
	}
	got := successResponseSchema(item, nil)
	if got == nil {
		t.Fatal("expected non-nil schema")
	}
	if got["type"] != "object" {
		t.Errorf("expected type=object, got %v", got["type"])
	}
}

// TestMergeParameters_FollowsRequestBodyRef is the regression test for the
// "warden schema sys/providers/{path} only shows path, not type/description/
// config" bug: the OAS request body is a $ref into components.schemas, and
// the merger must resolve it before reading properties.
func TestMergeParameters_FollowsRequestBodyRef(t *testing.T) {
	item := map[string]any{
		"post": map[string]any{
			"requestBody": map[string]any{
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": map[string]any{
							"$ref": "#/components/schemas/SysCreateProvidersPathRequest",
						},
					},
				},
			},
		},
	}
	components := map[string]any{
		"SysCreateProvidersPathRequest": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"type":        map[string]any{"type": "string", "description": "Provider type"},
				"description": map[string]any{"type": "string"},
				"config":      map[string]any{"type": "object"},
			},
			"required": []any{"type"},
		},
	}

	got := mergeParameters(item, components)
	names := make([]string, 0, len(got))
	for _, p := range got {
		names = append(names, p["name"].(string))
	}
	sort.Strings(names)

	want := []string{"config", "description", "type"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("after $ref resolution, params = %v; want %v (the referenced schema's properties)", names, want)
	}
	// Verify the required flag survives the resolution.
	for _, p := range got {
		if p["name"].(string) == "type" {
			if r, _ := p["required"].(bool); !r {
				t.Errorf("type should be required=true; got %#v", p)
			}
		}
	}
}

func TestResolveRef(t *testing.T) {
	components := map[string]any{
		"Foo": map[string]any{"type": "object", "x": 1},
	}

	t.Run("resolves ref", func(t *testing.T) {
		got := resolveRef(map[string]any{"$ref": "#/components/schemas/Foo"}, components)
		if got["x"] != 1 {
			t.Errorf("expected resolved schema, got %#v", got)
		}
	})
	t.Run("inline schema unchanged", func(t *testing.T) {
		inline := map[string]any{"type": "string"}
		got := resolveRef(inline, components)
		if got["type"] != "string" {
			t.Errorf("expected inline schema returned unchanged, got %#v", got)
		}
	})
	t.Run("unknown ref returns input", func(t *testing.T) {
		input := map[string]any{"$ref": "#/components/schemas/Missing"}
		got := resolveRef(input, components)
		if got["$ref"] != "#/components/schemas/Missing" {
			t.Errorf("unknown ref should fall back to input, got %#v", got)
		}
	})
	t.Run("non-components ref returns input", func(t *testing.T) {
		// "#/paths/foo" or external refs aren't resolvable here.
		input := map[string]any{"$ref": "https://example.com/spec.yaml#/Foo"}
		got := resolveRef(input, components)
		if got["$ref"] != "https://example.com/spec.yaml#/Foo" {
			t.Errorf("non-components ref should fall back to input, got %#v", got)
		}
	})
}

func TestExtractFirstError(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			"standard envelope",
			`{"errors":["path \"foo\" not found in schema"]}`,
			`path "foo" not found in schema`,
		},
		{
			"multiple errors keeps first",
			`{"errors":["first error","second error"]}`,
			"first error",
		},
		{
			"missing errors key falls back",
			`{"data": null}`,
			"schema endpoint returned 404",
		},
		{
			"empty errors array falls back",
			`{"errors":[]}`,
			"schema endpoint returned 404",
		},
		{
			"unparseable body falls back",
			`<html>404 Not Found</html>`,
			"schema endpoint returned 404",
		},
		{
			"empty body falls back",
			"",
			"schema endpoint returned 404",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFirstError([]byte(tt.body))
			if got != tt.want {
				t.Errorf("extractFirstError(%q) = %q; want %q", tt.body, got, tt.want)
			}
		})
	}
}

func TestRunSchema_FlagValidation(t *testing.T) {
	// Reset flag state between sub-tests so they don't leak into each other.
	t.Cleanup(func() {
		listAll = false
		raw = false
	})

	t.Run("no args + no --list rejects", func(t *testing.T) {
		listAll = false
		err := runSchema(nil, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "schema requires a PATH") {
			t.Errorf("error %q should mention requiring a PATH", err)
		}
	})

	t.Run("--list combined with PATH rejects", func(t *testing.T) {
		listAll = true
		err := runSchema(nil, []string{"sys/auth"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !contains(err.Error(), "cannot be combined") {
			t.Errorf("error %q should mention conflict between --list and PATH", err)
		}
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSuccessResponseSchema_NoSchema(t *testing.T) {
	item := map[string]any{
		"get": map[string]any{
			"responses": map[string]any{
				"200": map[string]any{
					"description": "empty body",
				},
			},
		},
	}
	if got := successResponseSchema(item, nil); got != nil {
		t.Errorf("expected nil for empty 200 response, got %#v", got)
	}
}
