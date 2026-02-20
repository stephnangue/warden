package credential

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FieldType represents the type of a configuration field
type FieldType int

const (
	FieldTypeString FieldType = iota
	FieldTypeInt
	FieldTypeDuration
	FieldTypeBool
	FieldTypeStringSlice
)

// String returns the string representation of the field type
func (ft FieldType) String() string {
	switch ft {
	case FieldTypeString:
		return "string"
	case FieldTypeInt:
		return "int"
	case FieldTypeDuration:
		return "duration"
	case FieldTypeBool:
		return "bool"
	case FieldTypeStringSlice:
		return "string slice"
	default:
		return "unknown"
	}
}

// FieldValidator provides a fluent API for building config field validators
type FieldValidator struct {
	fieldName   string
	required    bool
	fieldType   FieldType
	validator   func(string) error
	description string
	example     string
}

// StringField creates a validator for a string field
func StringField(name string) *FieldValidator {
	return &FieldValidator{
		fieldName: name,
		fieldType: FieldTypeString,
	}
}

// IntField creates a validator for an integer field
func IntField(name string) *FieldValidator {
	return &FieldValidator{
		fieldName: name,
		fieldType: FieldTypeInt,
	}
}

// DurationField creates a validator for a duration field
func DurationField(name string) *FieldValidator {
	return &FieldValidator{
		fieldName: name,
		fieldType: FieldTypeDuration,
	}
}

// BoolField creates a validator for a boolean field
func BoolField(name string) *FieldValidator {
	return &FieldValidator{
		fieldName: name,
		fieldType: FieldTypeBool,
	}
}

// StringSliceField creates a validator for a string slice field (comma-separated)
func StringSliceField(name string) *FieldValidator {
	return &FieldValidator{
		fieldName: name,
		fieldType: FieldTypeStringSlice,
	}
}

// Required marks the field as required
func (fv *FieldValidator) Required() *FieldValidator {
	fv.required = true
	return fv
}

// Range validates that an integer field is within the specified range (inclusive)
func (fv *FieldValidator) Range(min, max int) *FieldValidator {
	if fv.fieldType != FieldTypeInt {
		panic(fmt.Sprintf("Range() can only be used with IntField, got %s", fv.fieldType))
	}
	fv.validator = func(value string) error {
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("must be an integer")
		}
		if intVal < min || intVal > max {
			return fmt.Errorf("must be between %d and %d", min, max)
		}
		return nil
	}
	return fv
}

// Min validates that an integer field is at least the specified value
func (fv *FieldValidator) Min(min int) *FieldValidator {
	if fv.fieldType != FieldTypeInt {
		panic(fmt.Sprintf("Min() can only be used with IntField, got %s", fv.fieldType))
	}
	fv.validator = func(value string) error {
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("must be an integer")
		}
		if intVal < min {
			return fmt.Errorf("must be at least %d", min)
		}
		return nil
	}
	return fv
}

// Max validates that an integer field is at most the specified value
func (fv *FieldValidator) Max(max int) *FieldValidator {
	if fv.fieldType != FieldTypeInt {
		panic(fmt.Sprintf("Max() can only be used with IntField, got %s", fv.fieldType))
	}
	fv.validator = func(value string) error {
		intVal, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("must be an integer")
		}
		if intVal > max {
			return fmt.Errorf("must be at most %d", max)
		}
		return nil
	}
	return fv
}

// OneOf validates that the field value is one of the specified options
func (fv *FieldValidator) OneOf(values ...string) *FieldValidator {
	fv.validator = func(value string) error {
		for _, v := range values {
			if value == v {
				return nil
			}
		}
		return fmt.Errorf("must be one of: %s", strings.Join(values, ", "))
	}
	return fv
}

// Custom allows specifying a custom validation function
func (fv *FieldValidator) Custom(fn func(string) error) *FieldValidator {
	fv.validator = fn
	return fv
}

// Describe sets the description for this field (for documentation)
func (fv *FieldValidator) Describe(desc string) *FieldValidator {
	fv.description = desc
	return fv
}

// Example sets an example value for this field (for documentation)
func (fv *FieldValidator) Example(ex string) *FieldValidator {
	fv.example = ex
	return fv
}

// FieldName returns the name of the field
func (fv *FieldValidator) FieldName() string {
	return fv.fieldName
}

// IsRequired returns whether the field is required
func (fv *FieldValidator) IsRequired() bool {
	return fv.required
}

// Type returns the field type
func (fv *FieldValidator) Type() FieldType {
	return fv.fieldType
}

// Description returns the field description
func (fv *FieldValidator) Description() string {
	return fv.description
}

// ExampleValue returns the example value
func (fv *FieldValidator) ExampleValue() string {
	return fv.example
}

// Validate validates a single field value
func (fv *FieldValidator) Validate(value string) error {
	// Type validation
	if err := validateType(value, fv.fieldType); err != nil {
		return err
	}

	// Custom validation
	if fv.validator != nil {
		return fv.validator(value)
	}

	return nil
}

// ValidateSchema validates a config map against a schema defined by field validators
func ValidateSchema(config map[string]string, validators ...*FieldValidator) error {
	for _, fv := range validators {
		value, exists := config[fv.fieldName]

		// Check required
		if fv.required && (!exists || value == "") {
			return fmt.Errorf("field '%s' is required", fv.fieldName)
		}

		if !exists || value == "" {
			continue // Optional field not provided
		}

		// Validate field
		if err := fv.Validate(value); err != nil {
			return fmt.Errorf("field '%s': %w", fv.fieldName, err)
		}
	}

	return nil
}

// validateType validates that a string value can be parsed as the specified type
func validateType(value string, fieldType FieldType) error {
	if value == "" {
		return nil // Empty values are handled by Required() check
	}

	switch fieldType {
	case FieldTypeInt:
		if _, err := strconv.Atoi(value); err != nil {
			return fmt.Errorf("must be an integer")
		}
	case FieldTypeDuration:
		if _, err := time.ParseDuration(value); err != nil {
			return fmt.Errorf("must be a duration (e.g., '30s', '5m', '1h')")
		}
	case FieldTypeBool:
		if _, err := strconv.ParseBool(value); err != nil {
			return fmt.Errorf("must be a boolean (true/false)")
		}
	case FieldTypeStringSlice:
		// String slices are comma-separated strings, no validation needed
	case FieldTypeString:
		// Strings don't need type validation
	default:
		return fmt.Errorf("unsupported field type: %v", fieldType)
	}

	return nil
}

// GenerateConfigDocs generates markdown documentation for a config schema
func GenerateConfigDocs(driverType string, validators []*FieldValidator) string {
	if len(validators) == 0 {
		return ""
	}

	var buf strings.Builder

	buf.WriteString(fmt.Sprintf("## %s Configuration\n\n", driverType))
	buf.WriteString("| Field | Type | Required | Description | Example |\n")
	buf.WriteString("|-------|------|----------|-------------|----------|\n")

	for _, field := range validators {
		required := "No"
		if field.required {
			required = "Yes"
		}

		description := field.description
		if description == "" {
			description = "-"
		}

		example := field.example
		if example == "" {
			example = "-"
		}

		buf.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s | `%s` |\n",
			field.fieldName,
			field.fieldType.String(),
			required,
			description,
			example))
	}

	buf.WriteString("\n")
	return buf.String()
}
