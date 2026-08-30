package credential

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ConfigHelpers provides utility functions for parsing credential source config values
// Since all config values are stored as strings, drivers need to parse them to their expected types

// GetString returns the string value for a config key, or defaultValue if not found
func GetString(config map[string]string, key string, defaultValue string) string {
	if val, ok := config[key]; ok {
		return val
	}
	return defaultValue
}

// GetStringRequired returns the string value for a config key, or an error if not found
func GetStringRequired(config map[string]string, key string) (string, error) {
	if val, ok := config[key]; ok && val != "" {
		return val, nil
	}
	return "", fmt.Errorf("required config key '%s' not found or empty", key)
}

// GetInt returns the integer value for a config key, or defaultValue if not found or invalid
func GetInt(config map[string]string, key string, defaultValue int) int {
	if val, ok := config[key]; ok {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultValue
}

// GetIntRequired returns the integer value for a config key, or an error if not found or invalid
func GetIntRequired(config map[string]string, key string) (int, error) {
	val, ok := config[key]
	if !ok {
		return 0, fmt.Errorf("required config key '%s' not found", key)
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("config key '%s' must be an integer: %w", key, err)
	}
	return i, nil
}

// GetInt64 returns the int64 value for a config key, or defaultValue if not found or invalid
func GetInt64(config map[string]string, key string, defaultValue int64) int64 {
	if val, ok := config[key]; ok {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

// GetBool returns the boolean value for a config key, or defaultValue if not found or invalid
// Accepts: "true", "false", "1", "0", "yes", "no", "on", "off" (case-insensitive)
func GetBool(config map[string]string, key string, defaultValue bool) bool {
	if val, ok := config[key]; ok {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return defaultValue
}

// GetBoolRequired returns the boolean value for a config key, or an error if not found or invalid
func GetBoolRequired(config map[string]string, key string) (bool, error) {
	val, ok := config[key]
	if !ok {
		return false, fmt.Errorf("required config key '%s' not found", key)
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return false, fmt.Errorf("config key '%s' must be a boolean: %w", key, err)
	}
	return b, nil
}

// GetDuration returns the duration value for a config key, or defaultValue if not found or invalid
// Accepts duration strings like "30s", "5m", "1h", etc.
func GetDuration(config map[string]string, key string, defaultValue time.Duration) time.Duration {
	if val, ok := config[key]; ok {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultValue
}

// GetDurationRequired returns the duration value for a config key, or an error if not found or invalid
func GetDurationRequired(config map[string]string, key string) (time.Duration, error) {
	val, ok := config[key]
	if !ok {
		return 0, fmt.Errorf("required config key '%s' not found", key)
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("config key '%s' must be a valid duration: %w", key, err)
	}
	return d, nil
}

// GetPrefixed returns all config entries whose key starts with the given prefix,
// stripping the prefix from the returned keys. Keys equal to the prefix (empty
// suffix) are skipped. For example, with prefix "token_param.", a config key
// "token_param.resource" returns as "resource".
func GetPrefixed(config map[string]string, prefix string) map[string]string {
	result := make(map[string]string)
	for k, v := range config {
		if strings.HasPrefix(k, prefix) {
			stripped := strings.TrimPrefix(k, prefix)
			if stripped != "" {
				result[stripped] = v
			}
		}
	}
	return result
}

// ValidateRequired checks that all required config keys are present and non-empty
// Returns an error listing all missing keys if any are not found
func ValidateRequired(config map[string]string, requiredKeys ...string) error {
	var missing []string
	for _, key := range requiredKeys {
		if val, ok := config[key]; !ok || val == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config keys: %v", missing)
	}
	return nil
}

// ApplyKeyMap projects a fetched secret payload through the operator's
// "srcKey=destKey" selection, given as a comma-separated list. Each pair copies one
// source key into the result under its destination name; a pair whose source key is
// absent from the payload is skipped.
//
// The projection is deliberately exclusive: keys the spec does not name are dropped,
// so a spec vends exactly the fields its operator selected and nothing else that
// happens to be stored alongside them at the same path. An empty keyMapStr means no
// selection was configured, and the payload passes through untouched.
func ApplyKeyMap(data map[string]interface{}, keyMapStr string) map[string]interface{} {
	if keyMapStr == "" {
		return data
	}
	result := make(map[string]interface{})
	for _, pair := range strings.Split(keyMapStr, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 {
			srcKey := strings.TrimSpace(parts[0])
			destKey := strings.TrimSpace(parts[1])
			if val, ok := data[srcKey]; ok {
				result[destKey] = val
			}
		}
	}
	return result
}

// The two selection keys read a secret someone else wrote, but they do not apply to
// the same set of mint methods, so each carries its own list. Every mint method
// absent from a list builds its payload itself, and the key would be inert there.
var (
	// json_key_map projects a multi-field payload, so it applies wherever a fetch
	// returns a whole document to pick from.
	mintMethodsHonoringKeyMap = map[string]map[string]struct{}{
		SourceTypeVault: {"static_aws": {}, "static_apikey": {}, "kv2_read": {}},
		SourceTypeAWS:   {"secrets_manager": {}},
	}

	// secret_version pins a revision, which each store spells its own way: a
	// number for KV v2, an opaque identifier for Key Vault. A store that spells it
	// differently again (version_id / version_stage on Secrets Manager) is absent
	// here, so pinning there keeps using its own keys.
	mintMethodsHonoringSecretVersion = map[string]map[string]struct{}{
		SourceTypeVault: {"static_aws": {}, "static_apikey": {}, "kv2_read": {}},
		SourceTypeAzure: {"key_vault_secret": {}},
	}
)

// ValidateSecretSelection rejects the stored-secret selection keys on a spec whose
// mint method does not read a stored secret. Both keys fail open by nature — an
// ignored json_key_map vends the unprojected payload, and an ignored secret_version
// vends the current revision — so a spec setting them on the wrong mint method looks
// filtered or pinned while being neither. Rejecting at write time is the only point
// that sees the mint method and its source together.
//
// secret_version is narrower than json_key_map: a store with its own version
// addressing spells it differently (version_id / version_stage), so secret_version
// is accepted only where a numbered read applies.
func ValidateSecretSelection(config map[string]string, sourceType string) error {
	mintMethod := config["mint_method"]

	if keyMap := config["json_key_map"]; keyMap != "" {
		if _, ok := mintMethodsHonoringKeyMap[sourceType][mintMethod]; !ok {
			return fmt.Errorf("'json_key_map' selects fields of a stored secret and is not supported by mint_method '%s'; it applies to static_aws, static_apikey and kv2_read on an hvault source, and secrets_manager on an aws source", mintMethod)
		}
		if err := validateKeyMapSyntax(keyMap); err != nil {
			return err
		}
	}

	if _, ok := mintMethodsHonoringSecretVersion[sourceType][mintMethod]; !ok && config["secret_version"] != "" {
		return fmt.Errorf("'secret_version' pins a revision of a stored secret and is not supported by mint_method '%s'; it applies to static_aws, static_apikey and kv2_read on an hvault source, and key_vault_secret on an azure source", mintMethod)
	}

	return nil
}

// validateKeyMapSyntax checks that every pair names both a source and a
// destination. ApplyKeyMap skips a pair it cannot split, which would otherwise
// narrow the selection silently: the spec writes fine, mints fine, and vends a
// payload missing the field the operator meant to select. A duplicated destination
// is rejected for the same reason — one of the two sources would vanish with no
// indication which.
func validateKeyMapSyntax(keyMapStr string) error {
	seen := make(map[string]struct{})
	for _, pair := range strings.Split(keyMapStr, ",") {
		trimmed := strings.TrimSpace(pair)
		if trimmed == "" {
			return fmt.Errorf("'json_key_map' has an empty entry; each one must read 'srcKey=destKey'")
		}

		srcKey, destKey, split := strings.Cut(trimmed, "=")
		srcKey, destKey = strings.TrimSpace(srcKey), strings.TrimSpace(destKey)
		if !split || srcKey == "" || destKey == "" {
			return fmt.Errorf("'json_key_map' entry %q must read 'srcKey=destKey' with both names set", trimmed)
		}

		if _, dup := seen[destKey]; dup {
			return fmt.Errorf("'json_key_map' maps more than one field to '%s'; only one of them would be vended", destKey)
		}
		seen[destKey] = struct{}{}
	}
	return nil
}
