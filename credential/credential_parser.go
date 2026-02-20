package credential

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/logger"
)

// CredentialParser handles credential parsing and validation.
// It provides a focused abstraction for converting raw credential data from drivers
// into validated Credential structs using registered credential types.
//
// Responsibilities:
//   - Lookup credential type handler from TypeRegistry
//   - Parse raw data into structured Credential using Type.Parse()
//   - Set source metadata (SourceName, SourceType)
//   - Validate credential using Type.Validate()
//   - Return clear error messages for parsing/validation failures
//
// This component was extracted from Manager to:
//   - Reduce Manager's dependency count
//   - Improve testability (can mock TypeRegistry only)
//   - Provide single responsibility (credential parsing/validation)
//   - Enable future middleware (transformation, enrichment, redaction)
type CredentialParser struct {
	typeRegistry *TypeRegistry
	logger       *logger.GatedLogger
}

// NewCredentialParser creates a new CredentialParser instance
func NewCredentialParser(typeRegistry *TypeRegistry, logger *logger.GatedLogger) *CredentialParser {
	return &CredentialParser{
		typeRegistry: typeRegistry,
		logger:       logger,
	}
}

// ParseAndValidate parses raw credential data and validates the result.
// This is the main entry point for converting driver output into validated credentials.
//
// The parsing pipeline:
//  1. Lookup Type handler for spec.Type from TypeRegistry
//  2. Call Type.Parse() to convert rawData → Credential struct
//  3. Set source metadata (SourceName from spec, SourceType from driver)
//  4. Call Type.Validate() to ensure credential integrity
//  5. Return validated credential or error
//
// Parameters:
//   - ctx: Context with namespace information
//   - spec: The CredSpec defining the credential type and source
//   - rawData: Raw credential data from driver.MintCredential()
//   - leaseTTL: Time-to-live for the credential
//   - leaseID: Lease identifier for revocation at source
//   - driver: The source driver that minted the credential (for Type() method)
//
// Returns the validated Credential or an error
func (p *CredentialParser) ParseAndValidate(
	ctx context.Context,
	spec *CredSpec,
	rawData map[string]interface{},
	leaseTTL time.Duration,
	leaseID string,
	driver SourceDriver,
) (*Credential, error) {
	// Step 1: Get credential type handler
	credType, err := p.typeRegistry.GetByName(spec.Type)
	if err != nil {
		return nil, fmt.Errorf("credential type '%s' not found: %w", spec.Type, err)
	}

	// Step 2: Parse raw data into structured credential
	cred, err := credType.Parse(rawData, leaseTTL, leaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	// Step 3: Set source information
	cred.SourceName = spec.Source
	cred.SourceType = driver.Type()

	// Step 4: Validate credential
	if err := credType.Validate(cred); err != nil {
		return nil, fmt.Errorf("credential validation failed: %w", err)
	}

	return cred, nil
}
