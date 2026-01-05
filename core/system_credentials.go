package core

import (
	"context"
	"fmt"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
)

// Credential Source Handlers

// CreateCredentialSource creates a new credential source
func (h *SystemHandlers) CreateCredentialSource(
	ctx context.Context,
	input *CreateCredentialSourceInput,
) (*CreateCredentialSourceOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("create credential source operation unauthorized",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		h.logger.Error("namespace not found in context", logger.Err(err))
		return nil, huma.Error400BadRequest("namespace not found")
	}

	h.logger.Info("creating credential source",
		logger.String("name", input.Name),
		logger.String("type", input.Body.Type),
		logger.String("namespace", ns.Path))

	// Create credential source
	source := &credential.CredSource{
		Name:   input.Name,
		Type:   input.Body.Type,
		Config: input.Body.Config,
	}

	// Store via credential config store
	if err := h.core.credConfigStore.CreateSource(ctx, source); err != nil {
		h.logger.Error("failed to create credential source",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	// Return success
	output := &CreateCredentialSourceOutput{}
	output.Body.Name = source.Name
	output.Body.Type = source.Type
	output.Body.Config = source.Config
	output.Body.Message = fmt.Sprintf("Successfully created credential source %s", input.Name)

	return output, nil
}

// GetCredentialSource retrieves information about a specific credential source
func (h *SystemHandlers) GetCredentialSource(
	ctx context.Context,
	input *GetCredentialSourceInput,
) (*GetCredentialSourceOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("get credential source operation unauthorized",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		h.logger.Error("namespace not found in context", logger.Err(err))
		return nil, huma.Error400BadRequest("namespace not found")
	}

	h.logger.Debug("getting credential source",
		logger.String("name", input.Name),
		logger.String("namespace", ns.Path))

	// Retrieve from credential config store
	source, err := h.core.credConfigStore.GetSource(ctx, input.Name)
	if err != nil {
		h.logger.Error("failed to get credential source",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	// Return source information
	output := &GetCredentialSourceOutput{}
	output.Body.Name = source.Name
	output.Body.Type = source.Type
	output.Body.Config = source.Config

	return output, nil
}

// ListCredentialSources lists all credential sources
func (h *SystemHandlers) ListCredentialSources(
	ctx context.Context,
	input *ListCredentialSourcesInput,
) (*ListCredentialSourcesOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("list credential sources operation unauthorized",
			logger.Err(err))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		h.logger.Error("namespace not found in context", logger.Err(err))
		return nil, huma.Error400BadRequest("namespace not found")
	}

	h.logger.Debug("listing credential sources",
		logger.String("namespace", ns.Path))

	// Retrieve all sources from credential config store
	sources, err := h.core.credConfigStore.ListSources(ctx)
	if err != nil {
		h.logger.Error("failed to list credential sources", logger.Err(err))
		return nil, h.convertError(err)
	}

	// Convert to output format
	sourceInfos := make([]CredentialSourceInfo, 0, len(sources))
	for _, source := range sources {
		sourceInfos = append(sourceInfos, CredentialSourceInfo{
			Name:   source.Name,
			Type:   source.Type,
			Config: source.Config,
		})
	}

	output := &ListCredentialSourcesOutput{}
	output.Body.Sources = sourceInfos

	return output, nil
}

// UpdateCredentialSource updates an existing credential source
func (h *SystemHandlers) UpdateCredentialSource(
	ctx context.Context,
	input *UpdateCredentialSourceInput,
) (*UpdateCredentialSourceOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("update credential source operation unauthorized",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		h.logger.Error("namespace not found in context", logger.Err(err))
		return nil, huma.Error400BadRequest("namespace not found")
	}

	h.logger.Info("updating credential source",
		logger.String("name", input.Name),
		logger.String("namespace", ns.Path))

	// Get existing source
	source, err := h.core.credConfigStore.GetSource(ctx, input.Name)
	if err != nil {
		h.logger.Error("failed to get credential source for update",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	// Update config if provided
	if input.Body.Config != nil {
		source.Config = input.Body.Config
	}

	// Update via credential config store
	if err := h.core.credConfigStore.UpdateSource(ctx, source); err != nil {
		h.logger.Error("failed to update credential source",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	// Return success
	output := &UpdateCredentialSourceOutput{}
	output.Body.Name = source.Name
	output.Body.Message = fmt.Sprintf("Successfully updated credential source %s", input.Name)

	return output, nil
}

// DeleteCredentialSource deletes a credential source
func (h *SystemHandlers) DeleteCredentialSource(
	ctx context.Context,
	input *DeleteCredentialSourceInput,
) (*DeleteCredentialSourceOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("delete credential source operation unauthorized",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		h.logger.Error("namespace not found in context", logger.Err(err))
		return nil, huma.Error400BadRequest("namespace not found")
	}

	h.logger.Info("deleting credential source",
		logger.String("name", input.Name),
		logger.String("namespace", ns.Path))

	// Check for references before deletion
	references, err := h.core.credConfigStore.CheckSourceReferences(ctx, input.Name)
	if err != nil {
		h.logger.Error("failed to check source references",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	if len(references) > 0 {
		h.logger.Warn("cannot delete credential source: still referenced by specs",
			logger.String("name", input.Name),
			logger.Int("reference_count", len(references)))
		return nil, huma.Error400BadRequest(fmt.Sprintf("cannot delete credential source %s: still referenced by %d credential spec(s)", input.Name, len(references)))
	}

	// Delete via credential config store
	if err := h.core.credConfigStore.DeleteSource(ctx, input.Name); err != nil {
		h.logger.Error("failed to delete credential source",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	// Return success
	output := &DeleteCredentialSourceOutput{}
	output.Body.Message = fmt.Sprintf("Successfully deleted credential source %s", input.Name)

	return output, nil
}

// Credential Spec Handlers

// CreateCredentialSpec creates a new credential spec
func (h *SystemHandlers) CreateCredentialSpec(
	ctx context.Context,
	input *CreateCredentialSpecInput,
) (*CreateCredentialSpecOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("create credential spec operation unauthorized",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		h.logger.Error("namespace not found in context", logger.Err(err))
		return nil, huma.Error400BadRequest("namespace not found")
	}

	h.logger.Info("creating credential spec",
		logger.String("name", input.Name),
		logger.String("type", input.Body.Type),
		logger.String("source_name", input.Body.SourceName),
		logger.String("namespace", ns.Path))

	// Validate TTLs
	if input.Body.MinTTL < 0 || input.Body.MaxTTL < 0 {
		return nil, huma.Error400BadRequest("TTL values must be non-negative")
	}
	if input.Body.MinTTL > input.Body.MaxTTL && input.Body.MaxTTL != 0 {
		return nil, huma.Error400BadRequest("min_ttl cannot be greater than max_ttl")
	}

	// Create credential spec
	spec := &credential.CredSpec{
		Name:         input.Name,
		Type:         input.Body.Type,
		SourceName:   input.Body.SourceName,
		SourceParams: input.Body.SourceParams,
		MinTTL:       time.Duration(input.Body.MinTTL) * time.Second,
		MaxTTL:       time.Duration(input.Body.MaxTTL) * time.Second,
		TargetName:   input.Body.TargetName,
	}

	// Store via credential config store
	if err := h.core.credConfigStore.CreateSpec(ctx, spec); err != nil {
		h.logger.Error("failed to create credential spec",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	// Return success
	output := &CreateCredentialSpecOutput{}
	output.Body.Name = spec.Name
	output.Body.Type = spec.Type
	output.Body.SourceName = spec.SourceName
	output.Body.SourceParams = spec.SourceParams
	output.Body.MinTTL = int64(spec.MinTTL.Seconds())
	output.Body.MaxTTL = int64(spec.MaxTTL.Seconds())
	output.Body.TargetName = spec.TargetName
	output.Body.Message = fmt.Sprintf("Successfully created credential spec %s", input.Name)

	return output, nil
}

// GetCredentialSpec retrieves information about a specific credential spec
func (h *SystemHandlers) GetCredentialSpec(
	ctx context.Context,
	input *GetCredentialSpecInput,
) (*GetCredentialSpecOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("get credential spec operation unauthorized",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		h.logger.Error("namespace not found in context", logger.Err(err))
		return nil, huma.Error400BadRequest("namespace not found")
	}

	h.logger.Debug("getting credential spec",
		logger.String("name", input.Name),
		logger.String("namespace", ns.Path))

	// Retrieve from credential config store
	spec, err := h.core.credConfigStore.GetSpec(ctx, input.Name)
	if err != nil {
		h.logger.Error("failed to get credential spec",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	// Return spec information
	output := &GetCredentialSpecOutput{}
	output.Body.Name = spec.Name
	output.Body.Type = spec.Type
	output.Body.SourceName = spec.SourceName
	output.Body.SourceParams = spec.SourceParams
	output.Body.MinTTL = int64(spec.MinTTL.Seconds())
	output.Body.MaxTTL = int64(spec.MaxTTL.Seconds())
	output.Body.TargetName = spec.TargetName

	return output, nil
}

// ListCredentialSpecs lists all credential specs
func (h *SystemHandlers) ListCredentialSpecs(
	ctx context.Context,
	input *ListCredentialSpecsInput,
) (*ListCredentialSpecsOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("list credential specs operation unauthorized",
			logger.Err(err))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		h.logger.Error("namespace not found in context", logger.Err(err))
		return nil, huma.Error400BadRequest("namespace not found")
	}

	h.logger.Debug("listing credential specs",
		logger.String("namespace", ns.Path))

	// Retrieve all specs from credential config store
	specs, err := h.core.credConfigStore.ListSpecs(ctx)
	if err != nil {
		h.logger.Error("failed to list credential specs", logger.Err(err))
		return nil, h.convertError(err)
	}

	// Convert to output format
	specInfos := make([]CredentialSpecInfo, 0, len(specs))
	for _, spec := range specs {
		specInfos = append(specInfos, CredentialSpecInfo{
			Name:         spec.Name,
			Type:         spec.Type,
			SourceName:   spec.SourceName,
			SourceParams: spec.SourceParams,
			MinTTL:       int64(spec.MinTTL.Seconds()),
			MaxTTL:       int64(spec.MaxTTL.Seconds()),
			TargetName:   spec.TargetName,
		})
	}

	output := &ListCredentialSpecsOutput{}
	output.Body.Specs = specInfos

	return output, nil
}

// UpdateCredentialSpec updates an existing credential spec
func (h *SystemHandlers) UpdateCredentialSpec(
	ctx context.Context,
	input *UpdateCredentialSpecInput,
) (*UpdateCredentialSpecOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("update credential spec operation unauthorized",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		h.logger.Error("namespace not found in context", logger.Err(err))
		return nil, huma.Error400BadRequest("namespace not found")
	}

	h.logger.Info("updating credential spec",
		logger.String("name", input.Name),
		logger.String("namespace", ns.Path))

	// Get existing spec
	spec, err := h.core.credConfigStore.GetSpec(ctx, input.Name)
	if err != nil {
		h.logger.Error("failed to get credential spec for update",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	// Update fields if provided
	if input.Body.SourceParams != nil {
		spec.SourceParams = input.Body.SourceParams
	}
	if input.Body.MinTTL != nil {
		if *input.Body.MinTTL < 0 {
			return nil, huma.Error400BadRequest("min_ttl must be non-negative")
		}
		spec.MinTTL = time.Duration(*input.Body.MinTTL) * time.Second
	}
	if input.Body.MaxTTL != nil {
		if *input.Body.MaxTTL < 0 {
			return nil, huma.Error400BadRequest("max_ttl must be non-negative")
		}
		spec.MaxTTL = time.Duration(*input.Body.MaxTTL) * time.Second
	}

	// Validate TTLs
	if spec.MinTTL > spec.MaxTTL && spec.MaxTTL != 0 {
		return nil, huma.Error400BadRequest("min_ttl cannot be greater than max_ttl")
	}

	// Update via credential config store
	if err := h.core.credConfigStore.UpdateSpec(ctx, spec); err != nil {
		h.logger.Error("failed to update credential spec",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	// Return success
	output := &UpdateCredentialSpecOutput{}
	output.Body.Name = spec.Name
	output.Body.Message = fmt.Sprintf("Successfully updated credential spec %s", input.Name)

	return output, nil
}

// DeleteCredentialSpec deletes a credential spec
func (h *SystemHandlers) DeleteCredentialSpec(
	ctx context.Context,
	input *DeleteCredentialSpecInput,
) (*DeleteCredentialSpecOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("delete credential spec operation unauthorized",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Extract namespace from context
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		h.logger.Error("namespace not found in context", logger.Err(err))
		return nil, huma.Error400BadRequest("namespace not found")
	}

	h.logger.Info("deleting credential spec",
		logger.String("name", input.Name),
		logger.String("namespace", ns.Path))

	// Delete via credential config store
	if err := h.core.credConfigStore.DeleteSpec(ctx, input.Name); err != nil {
		h.logger.Error("failed to delete credential spec",
			logger.Err(err),
			logger.String("name", input.Name))
		return nil, h.convertError(err)
	}

	// Return success
	output := &DeleteCredentialSpecOutput{}
	output.Body.Message = fmt.Sprintf("Successfully deleted credential spec %s", input.Name)

	return output, nil
}
