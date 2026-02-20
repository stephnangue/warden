package credential

import (
	"fmt"
	"strings"
	"testing"
)

func TestFieldValidators(t *testing.T) {
	tests := []struct {
		name      string
		validator *FieldValidator
		value     string
		wantErr   bool
		errMsg    string
	}{
		// String field tests
		{
			name:      "string field - valid",
			validator: StringField("name"),
			value:     "test-value",
			wantErr:   false,
		},
		{
			name:      "string field - empty allowed when not required",
			validator: StringField("name"),
			value:     "",
			wantErr:   false,
		},

		// Int field tests
		{
			name:      "int field - valid",
			validator: IntField("count"),
			value:     "42",
			wantErr:   false,
		},
		{
			name:      "int field - invalid",
			validator: IntField("count"),
			value:     "not-a-number",
			wantErr:   true,
			errMsg:    "must be an integer",
		},
		{
			name:      "int field - valid range",
			validator: IntField("retries").Range(0, 10),
			value:     "5",
			wantErr:   false,
		},
		{
			name:      "int field - below range",
			validator: IntField("retries").Range(0, 10),
			value:     "-1",
			wantErr:   true,
			errMsg:    "must be between 0 and 10",
		},
		{
			name:      "int field - above range",
			validator: IntField("retries").Range(0, 10),
			value:     "11",
			wantErr:   true,
			errMsg:    "must be between 0 and 10",
		},
		{
			name:      "int field - min valid",
			validator: IntField("port").Min(1024),
			value:     "8080",
			wantErr:   false,
		},
		{
			name:      "int field - below min",
			validator: IntField("port").Min(1024),
			value:     "80",
			wantErr:   true,
			errMsg:    "must be at least 1024",
		},
		{
			name:      "int field - max valid",
			validator: IntField("percent").Max(100),
			value:     "75",
			wantErr:   false,
		},
		{
			name:      "int field - above max",
			validator: IntField("percent").Max(100),
			value:     "150",
			wantErr:   true,
			errMsg:    "must be at most 100",
		},

		// Duration field tests
		{
			name:      "duration field - valid seconds",
			validator: DurationField("timeout"),
			value:     "30s",
			wantErr:   false,
		},
		{
			name:      "duration field - valid minutes",
			validator: DurationField("timeout"),
			value:     "5m",
			wantErr:   false,
		},
		{
			name:      "duration field - valid hours",
			validator: DurationField("timeout"),
			value:     "2h",
			wantErr:   false,
		},
		{
			name:      "duration field - invalid",
			validator: DurationField("timeout"),
			value:     "30",
			wantErr:   true,
			errMsg:    "must be a duration",
		},

		// Bool field tests
		{
			name:      "bool field - true",
			validator: BoolField("enabled"),
			value:     "true",
			wantErr:   false,
		},
		{
			name:      "bool field - false",
			validator: BoolField("enabled"),
			value:     "false",
			wantErr:   false,
		},
		{
			name:      "bool field - 1",
			validator: BoolField("enabled"),
			value:     "1",
			wantErr:   false,
		},
		{
			name:      "bool field - 0",
			validator: BoolField("enabled"),
			value:     "0",
			wantErr:   false,
		},
		{
			name:      "bool field - invalid",
			validator: BoolField("enabled"),
			value:     "yes",
			wantErr:   true,
			errMsg:    "must be a boolean",
		},

		// OneOf tests
		{
			name:      "oneOf - valid",
			validator: StringField("region").OneOf("us-east-1", "us-west-2", "eu-west-1"),
			value:     "us-east-1",
			wantErr:   false,
		},
		{
			name:      "oneOf - invalid",
			validator: StringField("region").OneOf("us-east-1", "us-west-2"),
			value:     "ap-south-1",
			wantErr:   true,
			errMsg:    "must be one of",
		},

		// Custom validator tests
		{
			name: "custom - valid",
			validator: StringField("email").Custom(func(s string) error {
				if !strings.Contains(s, "@") {
					return fmt.Errorf("email must contain @")
				}
				return nil
			}),
			value:   "test@example.com",
			wantErr: false,
		},
		{
			name: "custom - invalid",
			validator: StringField("email").Custom(func(s string) error {
				if !strings.Contains(s, "@") {
					return fmt.Errorf("email must contain @")
				}
				return nil
			}),
			value:   "invalid-email",
			wantErr: true,
			errMsg:  "email must contain @",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.validator.Validate(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

func TestValidateSchema(t *testing.T) {
	tests := []struct {
		name       string
		config     map[string]string
		validators []*FieldValidator
		wantErr    bool
		errMsg     string
	}{
		{
			name: "all required fields present and valid",
			config: map[string]string{
				"name":    "test",
				"timeout": "30s",
				"retries": "3",
			},
			validators: []*FieldValidator{
				StringField("name").Required(),
				DurationField("timeout").Required(),
				IntField("retries").Range(0, 10),
			},
			wantErr: false,
		},
		{
			name: "missing required field",
			config: map[string]string{
				"timeout": "30s",
			},
			validators: []*FieldValidator{
				StringField("name").Required(),
				DurationField("timeout").Required(),
			},
			wantErr: true,
			errMsg:  "field 'name' is required",
		},
		{
			name: "empty required field",
			config: map[string]string{
				"name":    "",
				"timeout": "30s",
			},
			validators: []*FieldValidator{
				StringField("name").Required(),
				DurationField("timeout").Required(),
			},
			wantErr: true,
			errMsg:  "field 'name' is required",
		},
		{
			name: "optional field missing",
			config: map[string]string{
				"name": "test",
			},
			validators: []*FieldValidator{
				StringField("name").Required(),
				DurationField("timeout"), // Optional
			},
			wantErr: false,
		},
		{
			name: "invalid field value",
			config: map[string]string{
				"name":    "test",
				"retries": "not-a-number",
			},
			validators: []*FieldValidator{
				StringField("name").Required(),
				IntField("retries").Range(0, 10),
			},
			wantErr: true,
			errMsg:  "field 'retries': must be an integer",
		},
		{
			name: "field out of range",
			config: map[string]string{
				"name":    "test",
				"retries": "15",
			},
			validators: []*FieldValidator{
				StringField("name").Required(),
				IntField("retries").Range(0, 10),
			},
			wantErr: true,
			errMsg:  "field 'retries': must be between 0 and 10",
		},
		{
			name: "complex schema - all valid",
			config: map[string]string{
				"address":     "https://vault.example.com",
				"namespace":   "admin",
				"max_retries": "3",
				"timeout":     "30s",
				"tls_skip":    "false",
			},
			validators: []*FieldValidator{
				StringField("address").Required().Describe("Vault server address"),
				StringField("namespace").Describe("Vault namespace"),
				IntField("max_retries").Range(0, 10).Describe("Maximum retry attempts"),
				DurationField("timeout").Describe("Request timeout"),
				BoolField("tls_skip").Describe("Skip TLS verification"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSchema(tt.config, tt.validators...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSchema() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateSchema() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

func TestGenerateConfigDocs(t *testing.T) {
	validators := []*FieldValidator{
		StringField("address").
			Required().
			Describe("Vault server address").
			Example("https://vault.example.com"),
		IntField("max_retries").
			Range(0, 10).
			Describe("Maximum retry attempts").
			Example("3"),
		DurationField("timeout").
			Describe("Request timeout").
			Example("30s"),
		BoolField("tls_skip").
			Describe("Skip TLS verification").
			Example("false"),
	}

	docs := GenerateConfigDocs("vault", validators)

	// Check that documentation contains expected elements
	expectedStrings := []string{
		"## vault Configuration",
		"address",
		"max_retries",
		"timeout",
		"tls_skip",
		"string",
		"int",
		"duration",
		"bool",
		"Yes",  // Required
		"No",   // Not required
		"https://vault.example.com",
		"Vault server address",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(docs, expected) {
			t.Errorf("GenerateConfigDocs() missing expected string %q\nGot:\n%s", expected, docs)
		}
	}
}

func TestFieldValidatorAccessors(t *testing.T) {
	validator := StringField("test").
		Required().
		Describe("Test field").
		Example("test-value")

	if validator.FieldName() != "test" {
		t.Errorf("FieldName() = %v, want %v", validator.FieldName(), "test")
	}

	if !validator.IsRequired() {
		t.Error("IsRequired() = false, want true")
	}

	if validator.Type() != FieldTypeString {
		t.Errorf("Type() = %v, want %v", validator.Type(), FieldTypeString)
	}

	if validator.Description() != "Test field" {
		t.Errorf("Description() = %v, want %v", validator.Description(), "Test field")
	}

	if validator.ExampleValue() != "test-value" {
		t.Errorf("ExampleValue() = %v, want %v", validator.ExampleValue(), "test-value")
	}
}
