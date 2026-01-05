package credential

import "errors"

var (
	// ErrTypeNotFound is returned when a credential type is not found in the registry
	ErrTypeNotFound = errors.New("credential type not found")

	// ErrTypeAlreadyRegistered is returned when attempting to register a duplicate credential type
	ErrTypeAlreadyRegistered = errors.New("credential type already registered")

	// ErrDriverNotFound is returned when a driver is not found in the registry
	ErrDriverNotFound = errors.New("driver not found")

	// ErrDriverAlreadyRegistered is returned when attempting to register a duplicate driver factory
	ErrDriverAlreadyRegistered = errors.New("driver factory already registered")

	// ErrInvalidCredential is returned when credential validation fails
	ErrInvalidCredential = errors.New("invalid credential")

	// ErrRevocationFailed is returned when credential revocation fails
	ErrRevocationFailed = errors.New("credential revocation failed")

	// ErrDriverCreationFailed is returned when driver creation failed
	ErrDriverCreationFailed = errors.New("driver creation failed")

	// ErrCredentialNotFound is returned when a credential is not found in storage
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrSpecAlreadyExists is returned when attempting to register a spec that already exists
	ErrSpecAlreadyExists = errors.New("credential spec already exists")

	// ErrSourceAlreadyExists is returned when attempting to register a source that already exists
	ErrSourceAlreadyExists = errors.New("credential source already exists")
)
