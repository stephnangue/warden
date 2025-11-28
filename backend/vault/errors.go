package vault

import (
	"errors"
	"fmt"
)

var (
	ErrUnsupportedAuthMethod = func(authMethod string) error {
		return fmt.Errorf("unsupported authentication method: %s", authMethod)
	}
	ErrInvalidAuthResponse = errors.New("invalid authentication response from Vault")

	ErrFailedToCreateEntity = errors.New("failed to create entity")

	ErrFailedToRetrieveMount = errors.New("failed to retrieve mount information")
)
