package credential

import (
	"context"
	"fmt"
	"strings"
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

// warnUncarried logs the credential fields a mint had available but did not
// carry, so an upgrade that silently narrows a credential leaves a trace.
//
// Only names the type recognises as credential material are reported: an
// arbitrary key of a fetched secret is not a field anyone expected to travel, and
// warning about every one of them would bury the cases that matter.
func (p *CredentialParser) warnUncarried(credType Type, spec *CredSpec, rawData map[string]interface{}, cred *Credential) {
	if p.logger == nil {
		return
	}
	carrier, ok := credType.(AdjunctCarrier)
	if !ok {
		return
	}

	var dropped []string
	for _, field := range carrier.KnownAdjunctFields() {
		if _, carried := cred.Data[field]; carried {
			continue
		}
		if v, ok := rawData[field].(string); ok && v != "" {
			dropped = append(dropped, field)
		}
	}
	if len(dropped) == 0 {
		return
	}

	p.logger.Warn("credential field(s) available but not carried; declare them in the source's optional_metadata (an apikey source is required to carry them)",
		logger.String("spec", spec.Name),
		logger.String("source", spec.Source),
		logger.String("fields", strings.Join(dropped, ",")),
	)
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
//   - metadata: credential metadata from driver.MintCredential()
//   - leaseTTL: Time-to-live for the credential
//   - leaseID: Lease identifier for revocation at source
//   - driver: The source driver that minted the credential (for Type() method)
//
// Returns the validated Credential or an error
func (p *CredentialParser) ParseAndValidate(
	ctx context.Context,
	spec *CredSpec,
	rawData map[string]interface{},
	metadata map[string]interface{},
	leaseTTL time.Duration,
	leaseID string,
	driver SourceDriver,
) (*Credential, error) {
	// Step 1: Get credential type handler
	credType, err := p.typeRegistry.GetByName(spec.Type)
	if err != nil {
		return nil, fmt.Errorf("credential type '%s' not found: %w", spec.Type, err)
	}

	// Step 2: Take the driver's adjunct declaration out of rawData before parsing.
	//
	// Removal is unconditional, but the names are honoured only from the driver
	// that owns optional_metadata. Both halves are load-bearing. The vault and aws
	// drivers return fetched secret payloads verbatim, so this key can arrive from
	// someone's stored secret rather than from Warden — honouring it there would
	// let whoever writes that secret decide what becomes credential data. And
	// key_value's Parse copies every string key it is handed, so a key still in
	// rawData at parse time would land in the credential's Data itself.
	adjuncts := takeAdjunctNames(rawData)
	if driver.Type() != SourceTypeAPIKey {
		adjuncts = nil
	}

	// Step 3: Parse raw data and its metadata into structured credential
	cred, err := credType.Parse(rawData, metadata, leaseTTL, leaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	// Step 4: Set source information
	cred.SourceName = spec.Source
	cred.SourceType = driver.Type()

	// Step 5: Carry the declared adjuncts. After Parse, so the type's own fields
	// win; before Validate, so validation sees the finished credential.
	applyAdjunctCarriage(cred, rawData, adjuncts)

	// Step 5b: say so when a field that looks like credential material was
	// available and did not travel.
	//
	// Before adjunct carriage, some types copied a fixed set of extra fields from
	// whatever rawData any driver produced — so a spec on a local source, or a
	// Vault secret holding an organization id beside its key, carried them without
	// anyone declaring anything. Those credentials now mint without the field.
	// The spec-level guard cannot reach that case: it runs on write, and for a
	// fetched payload the field never appears in spec config at all.
	//
	// The failure is a provider quietly taking its fallback branch, which is
	// indistinguishable from a working mount. A log line is the only channel left.
	p.warnUncarried(credType, spec, rawData, cred)

	// Step 6: Validate credential
	if err := credType.Validate(cred); err != nil {
		return nil, fmt.Errorf("credential validation failed: %w", err)
	}

	return cred, nil
}
