package credential

import (
	"fmt"
	"regexp"
	"strings"
)

// Azure Key Vault naming rules, as Microsoft documents them for object identifiers:
// a vault name is 3-24 characters of 0-9, a-z, A-Z and '-', with no consecutive
// hyphens (and, per the resource-name rules, starting with a letter and ending with a
// letter or digit); a secret name is 1-127 characters of 0-9, a-z, A-Z and '-'; a
// version is a system-generated 32-character identifier.
//
// All three end up in a request URL — the vault name as a DNS label, the other two
// as path segments — so the checks are what keep a spec from reshaping the request:
// a name carrying '.', '/', '#' or '?' would otherwise send the Key Vault token to a
// different host or read a different object than the one the spec names.
var (
	keyVaultNamePattern          = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$`)
	keyVaultSecretNamePattern    = regexp.MustCompile(`^[0-9a-zA-Z-]{1,127}$`)
	keyVaultSecretVersionPattern = regexp.MustCompile(`^[0-9a-zA-Z]{32}$`)
)

// ValidateKeyVaultName checks a Key Vault name.
func ValidateKeyVaultName(name string) error {
	if !keyVaultNamePattern.MatchString(name) || strings.Contains(name, "--") {
		return fmt.Errorf("'vault_name' must be 3-24 letters, digits and hyphens, start with a letter, end with a letter or digit, and hold no consecutive hyphens, got: %s", name)
	}
	return nil
}

// ValidateKeyVaultSecretName checks a Key Vault secret name.
func ValidateKeyVaultSecretName(name string) error {
	if !keyVaultSecretNamePattern.MatchString(name) {
		return fmt.Errorf("'secret_name' must be 1-127 letters, digits and hyphens, got: %s", name)
	}
	return nil
}

// ValidateKeyVaultSecretVersion checks a Key Vault secret version identifier.
func ValidateKeyVaultSecretVersion(version string) error {
	if !keyVaultSecretVersionPattern.MatchString(version) {
		return fmt.Errorf("'secret_version' must be a 32-character Key Vault version identifier, got: %s", version)
	}
	return nil
}
