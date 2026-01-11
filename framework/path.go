// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package framework

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/stephnangue/warden/logical"
)

// GenericNameRegex returns a generic regex string for creating endpoint patterns
// that are identified by the given name in the backends
func GenericNameRegex(name string) string {
	return fmt.Sprintf("(?P<%s>\\w(([\\w-.]+)?\\w)?)", name)
}

// OptionalGenericNameRegex returns a regex string for optionally matching a name
func OptionalGenericNameRegex(name string) string {
	return fmt.Sprintf("(/(?P<%s>\\w(([\\w-.]+)?\\w)?))?", name)
}

// GenericNameWithAtRegex returns a generic regex that allows alphanumeric
// characters along with -, . and @.
func GenericNameWithAtRegex(name string) string {
	return fmt.Sprintf("(?P<%s>\\w(([\\w-.@]+)?\\w)?)", name)
}

// OptionalParamRegex returns a regex string for optionally accepting a field
// from the API URL
func OptionalParamRegex(name string) string {
	return fmt.Sprintf("(/(?P<%s>.+))?", name)
}

// MatchAllRegex returns a regex string for capturing an entire endpoint path
// as the given name.
func MatchAllRegex(name string) string {
	return fmt.Sprintf(`(?P<%s>.*)`, name)
}

// PathAppend is a helper for appending lists of paths into a single list.
func PathAppend(paths ...[]*Path) []*Path {
	result := make([]*Path, 0, 10)
	for _, ps := range paths {
		result = append(result, ps...)
	}
	return result
}

// Path is a single path that the backend responds to.
type Path struct {
	// Pattern is the pattern of the URL that matches this path.
	// This should be a valid regular expression. Named captures will be
	// exposed as fields that should map to a schema in Fields.
	// The pattern will automatically have a ^ prepended and a $ appended.
	Pattern string

	// Fields is the mapping of data fields to a schema describing that field.
	Fields map[string]*FieldSchema

	// Operations is the set of operations supported and the associated OperationsHandler.
	Operations map[logical.Operation]OperationHandler

	// Callbacks are the set of callbacks that are called for a given operation.
	// Deprecated: Operations should be used instead and will take priority if present.
	Callbacks map[logical.Operation]OperationFunc

	// ExistenceCheck, if implemented, is used to query whether a given
	// resource exists or not. This is used for ACL purposes.
	ExistenceCheck ExistenceFunc

	// Deprecated denotes that this path is considered deprecated.
	Deprecated bool

	// HelpSynopsis is a one-sentence description of the path.
	HelpSynopsis string

	// HelpDescription is a long-form description of the path.
	HelpDescription string

	// DisplayAttrs provides hints for UI and documentation generators.
	DisplayAttrs *DisplayAttributes

	// TakesArbitraryInput is used for endpoints that take arbitrary input.
	TakesArbitraryInput bool
}

// OperationHandler defines and describes a specific operation handler.
type OperationHandler interface {
	Handler() OperationFunc
	Properties() OperationProperties
}

// OperationProperties describes an operation for documentation, help text,
// and other clients.
type OperationProperties struct {
	// Summary is a brief (usually one line) description of the operation.
	Summary string

	// Description is extended documentation of the operation.
	Description string

	// Examples provides samples of the expected request data.
	Examples []RequestExample

	// Responses provides a list of response description for a given response code.
	Responses map[int][]Response

	// Unpublished indicates that this operation should not appear in public documentation.
	Unpublished bool

	// Deprecated indicates that this operation should be avoided.
	Deprecated bool

	// DisplayAttrs provides hints for UI and documentation generators.
	DisplayAttrs *DisplayAttributes
}

// DisplayAttributes provides hints for UI and documentation generators.
type DisplayAttributes struct {
	Name            string      `json:"name,omitempty"`
	Description     string      `json:"description,omitempty"`
	Value           interface{} `json:"value,omitempty"`
	Sensitive       bool        `json:"sensitive,omitempty"`
	Navigation      bool        `json:"navigation,omitempty"`
	ItemType        string      `json:"itemType,omitempty"`
	Group           string      `json:"group,omitempty"`
	Action          string      `json:"action,omitempty"`
	OperationPrefix string      `json:"operationPrefix,omitempty"`
	OperationVerb   string      `json:"operationVerb,omitempty"`
	OperationSuffix string      `json:"operationSuffix,omitempty"`
	EditType        string      `json:"editType,omitempty"`
}

// RequestExample is example of request data.
type RequestExample struct {
	Description string
	Data        map[string]interface{}
	Response    *Response
}

// Response describes an operation response.
type Response struct {
	Description string
	MediaType   string
	Fields      map[string]*FieldSchema
	Example     *logical.Response
	SchemaName  string
}

// PathOperation is a concrete implementation of OperationHandler.
type PathOperation struct {
	Callback     OperationFunc
	Summary      string
	Description  string
	Examples     []RequestExample
	Responses    map[int][]Response
	Unpublished  bool
	Deprecated   bool
	DisplayAttrs *DisplayAttributes
}

func (p *PathOperation) Handler() OperationFunc {
	return p.Callback
}

func (p *PathOperation) Properties() OperationProperties {
	return OperationProperties{
		Summary:      strings.TrimSpace(p.Summary),
		Description:  strings.TrimSpace(p.Description),
		Responses:    p.Responses,
		Examples:     p.Examples,
		Unpublished:  p.Unpublished,
		Deprecated:   p.Deprecated,
		DisplayAttrs: p.DisplayAttrs,
	}
}

// FieldSchema is a basic schema to describe the format of a path field.
type FieldSchema struct {
	Type        FieldType
	Default     interface{}
	Description string
	Required    bool
	Deprecated  bool
	Query       bool

	// AllowedValues is an optional list of permitted values for this field.
	AllowedValues []interface{}

	// DisplayAttrs provides hints for UI and documentation generators.
	DisplayAttrs *DisplayAttributes
}

// DefaultOrZero returns the default value if it is set, or otherwise
// the zero value of the type.
func (s *FieldSchema) DefaultOrZero() interface{} {
	if s.Default != nil {
		switch s.Type {
		case TypeDurationSecond, TypeSignedDurationSecond:
			resultDur, err := parseutil.ParseDurationSecond(s.Default)
			if err != nil {
				return s.Type.Zero()
			}
			return int(resultDur.Seconds())
		default:
			return s.Default
		}
	}
	return s.Type.Zero()
}

// Zero returns the correct zero-value for a specific FieldType
func (t FieldType) Zero() interface{} {
	switch t {
	case TypeString, TypeNameString, TypeLowerCaseString:
		return ""
	case TypeInt:
		return 0
	case TypeInt64:
		return int64(0)
	case TypeBool:
		return false
	case TypeMap:
		return map[string]interface{}{}
	case TypeKVPairs:
		return map[string]string{}
	case TypeDurationSecond, TypeSignedDurationSecond:
		return 0
	case TypeSlice:
		return []interface{}{}
	case TypeStringSlice, TypeCommaStringSlice:
		return []string{}
	case TypeCommaIntSlice:
		return []int{}
	case TypeHeader:
		return http.Header{}
	case TypeFloat:
		return 0.0
	case TypeTime:
		return time.Time{}
	default:
		panic("unknown type: " + t.String())
	}
}

func (p *Path) helpCallback(b *Backend) OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *FieldData) (*logical.Response, error) {
		var tplData pathTemplateData
		tplData.Request = req.Path
		tplData.RoutePattern = p.Pattern
		tplData.Synopsis = strings.TrimSpace(p.HelpSynopsis)
		if tplData.Synopsis == "" {
			tplData.Synopsis = "<no synopsis>"
		}
		tplData.Description = strings.TrimSpace(p.HelpDescription)
		if tplData.Description == "" {
			tplData.Description = "<no description>"
		}

		// Alphabetize the fields
		fieldKeys := make([]string, 0, len(p.Fields))
		for k := range p.Fields {
			fieldKeys = append(fieldKeys, k)
		}
		sort.Strings(fieldKeys)

		// Build the field help
		tplData.Fields = make([]pathTemplateFieldData, len(fieldKeys))
		for i, k := range fieldKeys {
			schema := p.Fields[k]
			description := strings.TrimSpace(schema.Description)
			if description == "" {
				description = "<no description>"
			}

			tplData.Fields[i] = pathTemplateFieldData{
				Key:         k,
				Type:        schema.Type.String(),
				Description: description,
				Deprecated:  schema.Deprecated,
			}
		}

		help, err := executeTemplate(pathHelpTemplate, &tplData)
		if err != nil {
			return nil, fmt.Errorf("error executing template: %w", err)
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"help": help,
			},
		}, nil
	}
}

type pathTemplateData struct {
	Request      string
	RoutePattern string
	Synopsis     string
	Description  string
	Fields       []pathTemplateFieldData
}

type pathTemplateFieldData struct {
	Key         string
	Type        string
	Deprecated  bool
	Description string
	URL         bool
}

const pathHelpTemplate = `
Request:        {{.Request}}
Matching Route: {{.RoutePattern}}

{{.Synopsis}}

{{ if .Fields -}}
## PARAMETERS
{{range .Fields}}
{{indent 4 .Key}} ({{.Type}})
{{if .Deprecated}}
{{printf "(DEPRECATED) %s" .Description | indent 8}}
{{else}}
{{indent 8 .Description}}
{{end}}{{end}}{{end}}
## DESCRIPTION

{{.Description}}
`
