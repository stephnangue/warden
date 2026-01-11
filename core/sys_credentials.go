package core

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathCredentials returns the paths for credential source and spec operations
func (b *SystemBackend) pathCredentials() []*framework.Path {
	return []*framework.Path{
		// Credential Sources
		{
			Pattern: "cred/sources/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "The credential source name",
					Required:    true,
				},
				"type": {
					Type:        framework.TypeString,
					Description: "The credential source type",
					Required:    true,
				},
				"config": {
					Type:        framework.TypeMap,
					Description: "Source-specific configuration",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleCredentialSourceCreate,
					Summary:  "Create a new credential source",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleCredentialSourceRead,
					Summary:  "Get credential source information",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleCredentialSourceUpdate,
					Summary:  "Update credential source",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleCredentialSourceDelete,
					Summary:  "Delete a credential source",
				},
			},
			HelpSynopsis:    "Manage credential sources",
			HelpDescription: "Create, read, update, and delete credential sources.",
		},
		{
			Pattern: "cred/sources/?$",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleCredentialSourceList,
					Summary:  "List all credential sources",
				},
			},
			HelpSynopsis:    "List credential sources",
			HelpDescription: "List all credential sources in the current namespace.",
		},
		// Credential Specs
		{
			Pattern: "cred/specs/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "The credential spec name",
					Required:    true,
				},
				"type": {
					Type:        framework.TypeString,
					Description: "The credential type",
					Required:    true,
				},
				"source_name": {
					Type:        framework.TypeString,
					Description: "The name of the credential source to use",
					Required:    true,
				},
				"source_params": {
					Type:        framework.TypeMap,
					Description: "Parameters to pass to the credential source",
				},
				"min_ttl": {
					Type:        framework.TypeInt,
					Description: "Minimum TTL in seconds",
					Default:     0,
				},
				"max_ttl": {
					Type:        framework.TypeInt,
					Description: "Maximum TTL in seconds",
					Default:     0,
				},
				"target_name": {
					Type:        framework.TypeString,
					Description: "The target name for the credential",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleCredentialSpecCreate,
					Summary:  "Create a new credential spec",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleCredentialSpecRead,
					Summary:  "Get credential spec information",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleCredentialSpecUpdate,
					Summary:  "Update credential spec",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleCredentialSpecDelete,
					Summary:  "Delete a credential spec",
				},
			},
			HelpSynopsis:    "Manage credential specs",
			HelpDescription: "Create, read, update, and delete credential specs.",
		},
		{
			Pattern: "cred/specs/?$",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleCredentialSpecList,
					Summary:  "List all credential specs",
				},
			},
			HelpSynopsis:    "List credential specs",
			HelpDescription: "List all credential specs in the current namespace.",
		},
	}
}

// convertToStringMap converts map[string]any to map[string]string
func convertToStringMap(m map[string]any) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			result[k] = s
		} else {
			result[k] = fmt.Sprintf("%v", v)
		}
	}
	return result
}

// Credential Source Handlers

// handleCredentialSourceCreate handles POST /sys/cred/sources/{name}
func (b *SystemBackend) handleCredentialSourceCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	sourceType := d.Get("type").(string)
	configAny, _ := d.Get("config").(map[string]any)

	b.logger.Info("creating credential source",
		logger.String("name", name),
		logger.String("type", sourceType))

	// Create credential source
	source := &credential.CredSource{
		Name:   name,
		Type:   sourceType,
		Config: convertToStringMap(configAny),
	}

	// Store via credential config store
	if err := b.core.credConfigStore.CreateSource(ctx, source); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondCreated(map[string]any{
		"name":    source.Name,
		"type":    source.Type,
		"config":  source.Config,
		"message": fmt.Sprintf("Successfully created credential source %s", name),
	}), nil
}

// handleCredentialSourceRead handles GET /sys/cred/sources/{name}
func (b *SystemBackend) handleCredentialSourceRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Retrieve from credential config store
	source, err := b.core.credConfigStore.GetSource(ctx, name)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"name":   source.Name,
		"type":   source.Type,
		"config": source.Config,
	}), nil
}

// handleCredentialSourceUpdate handles PUT /sys/cred/sources/{name}
func (b *SystemBackend) handleCredentialSourceUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	configAny, _ := d.Get("config").(map[string]any)

	b.logger.Info("updating credential source", logger.String("name", name))

	// Get existing source
	source, err := b.core.credConfigStore.GetSource(ctx, name)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	// Update config if provided
	if configAny != nil {
		source.Config = convertToStringMap(configAny)
	}

	// Update via credential config store
	if err := b.core.credConfigStore.UpdateSource(ctx, source); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"name":    source.Name,
		"message": fmt.Sprintf("Successfully updated credential source %s", name),
	}), nil
}

// handleCredentialSourceDelete handles DELETE /sys/cred/sources/{name}
func (b *SystemBackend) handleCredentialSourceDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	b.logger.Info("deleting credential source", logger.String("name", name))

	// Check for references before deletion
	references, err := b.core.credConfigStore.CheckSourceReferences(ctx, name)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	if len(references) > 0 {
		b.logger.Warn("cannot delete credential source: still referenced by specs",
			logger.String("name", name),
			logger.Int("reference_count", len(references)))
		return logical.ErrorResponse(logical.ErrConflictf(
			"cannot delete credential source %s: still referenced by %d credential spec(s)",
			name, len(references))), nil
	}

	// Delete via credential config store
	if err := b.core.credConfigStore.DeleteSource(ctx, name); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"message": fmt.Sprintf("Successfully deleted credential source %s", name),
	}), nil
}

// handleCredentialSourceList handles GET /sys/cred/sources
func (b *SystemBackend) handleCredentialSourceList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Retrieve all sources from credential config store
	sources, err := b.core.credConfigStore.ListSources(ctx)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	// Convert to output format
	sourceInfos := make([]map[string]any, 0, len(sources))
	for _, source := range sources {
		sourceInfos = append(sourceInfos, map[string]any{
			"name":   source.Name,
			"type":   source.Type,
			"config": source.Config,
		})
	}

	return b.respondSuccess(map[string]any{
		"sources": sourceInfos,
	}), nil
}

// Credential Spec Handlers

// handleCredentialSpecCreate handles POST /sys/cred/specs/{name}
func (b *SystemBackend) handleCredentialSpecCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	specType := d.Get("type").(string)
	sourceName := d.Get("source_name").(string)
	sourceParamsAny, _ := d.Get("source_params").(map[string]any)
	minTTL, _ := d.Get("min_ttl").(int)
	maxTTL, _ := d.Get("max_ttl").(int)
	targetName, _ := d.Get("target_name").(string)

	b.logger.Info("creating credential spec",
		logger.String("name", name),
		logger.String("type", specType),
		logger.String("source_name", sourceName))

	// Validate TTLs
	if minTTL < 0 || maxTTL < 0 {
		return logical.ErrorResponse(logical.ErrBadRequest("TTL values must be non-negative")), nil
	}
	if minTTL > maxTTL && maxTTL != 0 {
		return logical.ErrorResponse(logical.ErrBadRequest("min_ttl cannot be greater than max_ttl")), nil
	}

	// Create credential spec
	spec := &credential.CredSpec{
		Name:         name,
		Type:         specType,
		SourceName:   sourceName,
		SourceParams: convertToStringMap(sourceParamsAny),
		MinTTL:       time.Duration(minTTL) * time.Second,
		MaxTTL:       time.Duration(maxTTL) * time.Second,
		TargetName:   targetName,
	}

	// Store via credential config store
	if err := b.core.credConfigStore.CreateSpec(ctx, spec); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondCreated(map[string]any{
		"name":          spec.Name,
		"type":          spec.Type,
		"source_name":   spec.SourceName,
		"source_params": spec.SourceParams,
		"min_ttl":       int64(spec.MinTTL.Seconds()),
		"max_ttl":       int64(spec.MaxTTL.Seconds()),
		"target_name":   spec.TargetName,
		"message":       fmt.Sprintf("Successfully created credential spec %s", name),
	}), nil
}

// handleCredentialSpecRead handles GET /sys/cred/specs/{name}
func (b *SystemBackend) handleCredentialSpecRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Retrieve from credential config store
	spec, err := b.core.credConfigStore.GetSpec(ctx, name)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"name":          spec.Name,
		"type":          spec.Type,
		"source_name":   spec.SourceName,
		"source_params": spec.SourceParams,
		"min_ttl":       int64(spec.MinTTL.Seconds()),
		"max_ttl":       int64(spec.MaxTTL.Seconds()),
		"target_name":   spec.TargetName,
	}), nil
}

// handleCredentialSpecUpdate handles PUT /sys/cred/specs/{name}
func (b *SystemBackend) handleCredentialSpecUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	b.logger.Info("updating credential spec", logger.String("name", name))

	// Get existing spec
	spec, err := b.core.credConfigStore.GetSpec(ctx, name)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	// Update fields if provided
	if sourceParamsAny, ok := d.GetOk("source_params"); ok {
		spec.SourceParams = convertToStringMap(sourceParamsAny.(map[string]any))
	}

	if minTTL, ok := d.GetOk("min_ttl"); ok {
		ttl := minTTL.(int)
		if ttl < 0 {
			return logical.ErrorResponse(logical.ErrBadRequest("min_ttl must be non-negative")), nil
		}
		spec.MinTTL = time.Duration(ttl) * time.Second
	}

	if maxTTL, ok := d.GetOk("max_ttl"); ok {
		ttl := maxTTL.(int)
		if ttl < 0 {
			return logical.ErrorResponse(logical.ErrBadRequest("max_ttl must be non-negative")), nil
		}
		spec.MaxTTL = time.Duration(ttl) * time.Second
	}

	// Validate TTLs
	if spec.MinTTL > spec.MaxTTL && spec.MaxTTL != 0 {
		return logical.ErrorResponse(logical.ErrBadRequest("min_ttl cannot be greater than max_ttl")), nil
	}

	// Update via credential config store
	if err := b.core.credConfigStore.UpdateSpec(ctx, spec); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"name":    spec.Name,
		"message": fmt.Sprintf("Successfully updated credential spec %s", name),
	}), nil
}

// handleCredentialSpecDelete handles DELETE /sys/cred/specs/{name}
func (b *SystemBackend) handleCredentialSpecDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	b.logger.Info("deleting credential spec", logger.String("name", name))

	// Delete via credential config store
	if err := b.core.credConfigStore.DeleteSpec(ctx, name); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"message": fmt.Sprintf("Successfully deleted credential spec %s", name),
	}), nil
}

// handleCredentialSpecList handles GET /sys/cred/specs
func (b *SystemBackend) handleCredentialSpecList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Retrieve all specs from credential config store
	specs, err := b.core.credConfigStore.ListSpecs(ctx)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	// Convert to output format
	specInfos := make([]map[string]any, 0, len(specs))
	for _, spec := range specs {
		specInfos = append(specInfos, map[string]any{
			"name":          spec.Name,
			"type":          spec.Type,
			"source_name":   spec.SourceName,
			"source_params": spec.SourceParams,
			"min_ttl":       int64(spec.MinTTL.Seconds()),
			"max_ttl":       int64(spec.MaxTTL.Seconds()),
			"target_name":   spec.TargetName,
		})
	}

	return b.respondSuccess(map[string]any{
		"specs": specInfos,
	}), nil
}
