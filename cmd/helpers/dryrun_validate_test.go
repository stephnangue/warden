package helpers

import (
	"errors"
	"strings"
	"testing"
)

// validatePayload + Levenshtein "did you mean" exercise the validator's
// pure-function half. The HTTP-fetch path (loadBodySchema) is exercised
// in e2e/auth/dryrun_test.go against a real server.

func makeSchema(props map[string]propertySchema, required ...string) bodySchema {
	bs := bodySchema{
		properties: props,
		required:   map[string]bool{},
	}
	for _, r := range required {
		bs.required[r] = true
	}
	for name := range props {
		bs.knownNames = append(bs.knownNames, name)
	}
	return bs
}

func TestValidatePayload_Clean(t *testing.T) {
	bs := makeSchema(map[string]propertySchema{
		"type":          {typ: "string"},
		"max_body_size": {typ: "integer"},
	}, "type")
	got := validatePayload(map[string]any{"type": "aws", "max_body_size": int64(1024)}, bs)
	if len(got) != 0 {
		t.Fatalf("expected no problems for valid payload; got %v", got)
	}
}

func TestValidatePayload_RejectsMissingRequired(t *testing.T) {
	bs := makeSchema(map[string]propertySchema{
		"type": {typ: "string"},
	}, "type")
	got := validatePayload(map[string]any{}, bs)
	if len(got) != 1 || !strings.Contains(got[0], `"type"`) || !strings.Contains(got[0], "missing") {
		t.Errorf("expected required-missing error; got %v", got)
	}
}

func TestValidatePayload_RejectsUnknownField_WithSuggestion(t *testing.T) {
	bs := makeSchema(map[string]propertySchema{
		"max_body_size": {typ: "integer"},
		"timeout":       {typ: "string"},
	})
	got := validatePayload(map[string]any{"max_body_siz": 1024}, bs)
	if len(got) != 1 {
		t.Fatalf("expected exactly one problem; got %v", got)
	}
	if !strings.Contains(got[0], "max_body_size") {
		t.Errorf("expected Levenshtein suggestion for typo; got %q", got[0])
	}
}

func TestValidatePayload_NoSuggestionForFarTypos(t *testing.T) {
	bs := makeSchema(map[string]propertySchema{
		"type": {typ: "string"},
	})
	got := validatePayload(map[string]any{"completely_unrelated_field": "x"}, bs)
	if len(got) != 1 {
		t.Fatalf("expected one problem; got %v", got)
	}
	if strings.Contains(got[0], "did you mean") {
		t.Errorf("should not guess at far-off typos; got %q", got[0])
	}
}

func TestValidatePayload_RejectsTypeMismatch(t *testing.T) {
	bs := makeSchema(map[string]propertySchema{
		"max_body_size": {typ: "integer"},
	})
	got := validatePayload(map[string]any{"max_body_size": "ten kibibytes"}, bs)
	if len(got) != 1 || !strings.Contains(got[0], "max_body_size") || !strings.Contains(got[0], "integer") {
		t.Errorf("expected integer/type error; got %v", got)
	}
}

func TestValidatePayload_RejectsEnumMismatch(t *testing.T) {
	bs := makeSchema(map[string]propertySchema{
		"mode": {typ: "string", allowedValues: []any{"jwt", "oidc"}},
	})
	got := validatePayload(map[string]any{"mode": "ldap"}, bs)
	if len(got) != 1 || !strings.Contains(got[0], "ldap") {
		t.Errorf("expected enum error mentioning rejected value; got %v", got)
	}
}

func TestValidatePayload_AcceptsJSONNumberShapes(t *testing.T) {
	// Real-world payloads decoded from JSON often hand back float64 for
	// integers. The validator must not reject those.
	bs := makeSchema(map[string]propertySchema{
		"max_body_size": {typ: "integer"},
	})
	cases := []any{int(1024), int64(1024), float64(1024)}
	for _, v := range cases {
		got := validatePayload(map[string]any{"max_body_size": v}, bs)
		if len(got) != 0 {
			t.Errorf("expected %T %v to validate; got %v", v, v, got)
		}
	}
}

func TestValidatePayload_AcceptsObjectField(t *testing.T) {
	bs := makeSchema(map[string]propertySchema{
		"config": {typ: "object"},
	})
	got := validatePayload(map[string]any{
		"config": map[string]any{"region": "us-east-1"},
	}, bs)
	if len(got) != 0 {
		t.Errorf("expected object payload to validate; got %v", got)
	}
}

func TestValidatePayload_AcceptsNullForAnyType(t *testing.T) {
	// JSON null is treated as omission server-side; client mirrors that.
	bs := makeSchema(map[string]propertySchema{
		"description": {typ: "string"},
	})
	got := validatePayload(map[string]any{"description": nil}, bs)
	if len(got) != 0 {
		t.Errorf("null should validate against any type; got %v", got)
	}
}

func TestValidatePayload_SkipsTypeCheckWhenSchemaTypeBlank(t *testing.T) {
	// Some schemas omit `type` (e.g. when allowing multiple types). The
	// validator should not reject — the server is the authority on those.
	bs := makeSchema(map[string]propertySchema{
		"flexible": {},
	})
	got := validatePayload(map[string]any{"flexible": 42}, bs)
	if len(got) != 0 {
		t.Errorf("expected pass when schema type is blank; got %v", got)
	}
}

func TestValidatePayload_AggregatesAllProblems(t *testing.T) {
	// Agents iterate faster when they see every problem in one validation
	// round trip, not one-at-a-time.
	bs := makeSchema(map[string]propertySchema{
		"type":          {typ: "string"},
		"max_body_size": {typ: "integer"},
	}, "type")
	got := validatePayload(map[string]any{
		"max_body_size": "ten",
		"unknown":       true,
	}, bs)
	if len(got) < 3 {
		t.Errorf("expected ≥3 problems (missing required + type mismatch + unknown); got %v", got)
	}
}

func TestFormatValidationError_WrapsErrInvalidInput(t *testing.T) {
	err := formatValidationError([]string{"required field \"name\" is missing"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected wrapping ErrInvalidInput; got %v", err)
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("expected message in wrapped error; got %q", err.Error())
	}
}

func TestLevenshtein_ExpectedDistances(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"kitten", "sitting", 3},
		{"foo", "foo", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"max_body_siz", "max_body_size", 1},
		{"max_body_size", "max_body_siez", 2},
	}
	for _, tt := range cases {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			if got := levenshtein(tt.a, tt.b); got != tt.want {
				t.Errorf("levenshtein(%q,%q) = %d; want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestClosestName_PicksClosestWithinThreshold(t *testing.T) {
	candidates := []string{"max_body_size", "timeout", "proxy_domains"}
	cases := []struct {
		input string
		want  string
	}{
		{"max_body_siz", "max_body_size"},     // distance 1
		{"timeut", "timeout"},                 // distance 1
		{"completely_unrelated_field", ""},    // beyond threshold
		{"proxy_domain", "proxy_domains"},     // distance 1 (length diff)
		{"PROXY_DOMAINS", "proxy_domains"},    // case-insensitive match
	}
	for _, tt := range cases {
		t.Run(tt.input, func(t *testing.T) {
			if got := closestName(tt.input, candidates); got != tt.want {
				t.Errorf("closestName(%q) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractBodySchema_NoOperationOrBody(t *testing.T) {
	// Path exists but the GET operation has no requestBody — typical for
	// reads. Validator should return notDocumented=true.
	doc := map[string]any{
		"paths": map[string]any{
			"/sys/something": map[string]any{
				"get": map[string]any{},
			},
		},
	}
	bs := extractBodySchema(doc, "POST")
	if !bs.notDocumented {
		t.Errorf("expected notDocumented=true when method missing; got %#v", bs)
	}
}

func TestExtractBodySchema_ResolvesRef(t *testing.T) {
	doc := map[string]any{
		"paths": map[string]any{
			"/sys/cred/sources/{name}": map[string]any{
				"post": map[string]any{
					"requestBody": map[string]any{
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{
									"$ref": "#/components/schemas/Foo",
								},
							},
						},
					},
				},
			},
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"Foo": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"type": map[string]any{"type": "string"},
					},
					"required": []any{"type"},
				},
			},
		},
	}
	bs := extractBodySchema(doc, "POST")
	if bs.notDocumented {
		t.Fatal("expected resolved schema; got notDocumented")
	}
	if !bs.required["type"] {
		t.Errorf("expected required[type]=true after $ref resolution; got %#v", bs.required)
	}
	if _, ok := bs.properties["type"]; !ok {
		t.Errorf("expected properties[type] after $ref resolution; got %#v", bs.properties)
	}
}
