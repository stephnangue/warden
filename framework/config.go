package framework

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/logical"
)

const (
	// MaxBodySizeLimit is the maximum allowed value for max_body_size (100MB).
	MaxBodySizeLimit = 104857600
)

// ParseMaxBodySize extracts max_body_size from config.
// Handles int, int64, float64, json.Number, and string.
// Returns DefaultMaxBodySize if missing or invalid.
func ParseMaxBodySize(conf map[string]any) int64 {
	maxSize, ok := conf["max_body_size"]
	if !ok {
		return DefaultMaxBodySize
	}
	switch v := maxSize.(type) {
	case int:
		if v > 0 {
			return int64(v)
		}
	case int64:
		if v > 0 {
			return v
		}
	case float64:
		if v > 0 {
			return int64(v)
		}
	case json.Number:
		if parsed, err := v.Int64(); err == nil && parsed > 0 {
			return parsed
		}
	case string:
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			return parsed
		}
	}
	return DefaultMaxBodySize
}

// ParseTimeout extracts timeout from config.
// Handles string (duration format) and int/float64 (seconds).
// Returns defaultTimeout if missing or invalid.
func ParseTimeout(conf map[string]any, defaultTimeout time.Duration) time.Duration {
	timeout, ok := conf["timeout"]
	if !ok {
		return defaultTimeout
	}
	switch v := timeout.(type) {
	case string:
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			return parsed
		}
	case int:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	case float64:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	return defaultTimeout
}

// ParseTLSConfig extracts tls_skip_verify and ca_data from config.
func ParseTLSConfig(conf map[string]any) (tlsSkipVerify bool, caData string) {
	if v, ok := conf["tls_skip_verify"]; ok {
		switch b := v.(type) {
		case bool:
			tlsSkipVerify = b
		case string:
			tlsSkipVerify = b == "true" || b == "1"
		}
	}
	if v, ok := conf["ca_data"].(string); ok {
		caData = v
	}
	return
}

// GetConfigString extracts a string value from config with a default.
func GetConfigString(conf map[string]any, key, defaultValue string) string {
	if v, ok := conf[key].(string); ok && v != "" {
		return v
	}
	return defaultValue
}

// ValidateAllowedKeys checks that all keys in conf are in the allowed set.
func ValidateAllowedKeys(conf map[string]any, allowed ...string) error {
	allowedSet := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		allowedSet[k] = true
	}
	for key := range conf {
		if !allowedSet[key] {
			sort.Strings(allowed)
			return fmt.Errorf("unknown configuration key: %s (allowed: %s)", key, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// ValidateMaxBodySize validates that max_body_size is a valid integer within bounds.
func ValidateMaxBodySize(conf map[string]any) error {
	maxSize, ok := conf["max_body_size"]
	if !ok {
		return nil
	}
	var size int64
	switch v := maxSize.(type) {
	case int:
		size = int64(v)
	case int64:
		size = v
	case float64:
		size = int64(v)
	case json.Number:
		parsed, err := v.Int64()
		if err != nil {
			return fmt.Errorf("max_body_size must be an integer: %w", err)
		}
		size = parsed
	case string:
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("max_body_size must be an integer: %w", err)
		}
		size = parsed
	default:
		return fmt.Errorf("max_body_size must be an integer, got %T", maxSize)
	}
	if size <= 0 {
		return fmt.Errorf("max_body_size must be greater than 0")
	}
	if size > MaxBodySizeLimit {
		return fmt.Errorf("max_body_size must not exceed %d bytes (100MB)", MaxBodySizeLimit)
	}
	return nil
}

// ValidateTimeout validates that timeout is a positive duration string or
// integer. Zero is refused: the timeout is the deadline of every forwarded
// request and the only bound on how long an upstream may take, so it cannot
// be turned off.
func ValidateTimeout(conf map[string]any) error {
	timeout, ok := conf["timeout"]
	if !ok {
		return nil
	}
	switch v := timeout.(type) {
	case string:
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid timeout format: %w (expected format: '30s', '5m', '1h')", err)
		}
		if d <= 0 {
			return fmt.Errorf("timeout must be greater than 0")
		}
	case int:
		// Whole seconds: a config write's "500ms" arrives here as 0.
		if v <= 0 {
			return fmt.Errorf("timeout must be at least 1s")
		}
	case float64:
		if v <= 0 {
			return fmt.Errorf("timeout must be at least 1s")
		}
	default:
		return fmt.Errorf("timeout must be a duration string (e.g., '30s') or integer (seconds)")
	}
	return nil
}

// ValidateTLSConfig validates tls_skip_verify and ca_data fields.
func ValidateTLSConfig(conf map[string]any) error {
	if v, ok := conf["tls_skip_verify"]; ok {
		switch v := v.(type) {
		case bool:
			// valid
		case string:
			if v != "true" && v != "false" && v != "1" && v != "0" {
				return fmt.Errorf("tls_skip_verify must be a boolean, got string: %s", v)
			}
		default:
			return fmt.Errorf("tls_skip_verify must be a boolean, got %T", v)
		}
	}
	if v, ok := conf["ca_data"]; ok {
		caStr, ok := v.(string)
		if !ok {
			return fmt.Errorf("ca_data must be a string")
		}
		if caStr != "" {
			pemBytes, err := base64.StdEncoding.DecodeString(caStr)
			if err != nil {
				return fmt.Errorf("ca_data is not valid base64: %w", err)
			}
			block, _ := pem.Decode(pemBytes)
			if block == nil {
				return fmt.Errorf("ca_data contains no valid PEM data")
			}
		}
	}
	return nil
}

// NewTLSClientConfig builds the client TLS settings for an upstream connection
// from the two config fields ValidateTLSConfig checks: a base64-encoded PEM
// bundle to trust, and whether to verify at all.
//
// caData replaces the system roots rather than adding to them: a mount naming a
// private authority is saying which authority signs its upstream, and silently
// continuing to accept every public CA would not be that.
//
// The caller owns HTTP/2 setup. ConfigureTransport binds to whichever
// tls.Config is installed when it runs, so a transport must assign the result
// of this call before configuring h2, never after.
func NewTLSClientConfig(caData string, skipVerify bool) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
		InsecureSkipVerify: skipVerify,
	}

	if caData == "" {
		return cfg, nil
	}

	pemBytes, err := base64.StdEncoding.DecodeString(caData)
	if err != nil {
		return nil, fmt.Errorf("ca_data is not valid base64: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("ca_data contains no valid PEM certificates")
	}
	cfg.RootCAs = pool

	return cfg, nil
}

// ValidateURL validates that a URL is well-formed with an https:// scheme.
// When tlsSkipVerify is true, http:// is also accepted for dev/test environments.
// urlKey is used in error messages (e.g., "scaleway_url", "openai_url").
func ValidateURL(addr string, urlKey string, tlsSkipVerify bool) error {
	if addr == "" {
		return nil
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", urlKey, err)
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme == "http" && tlsSkipVerify {
			// Allow HTTP when TLS verification is disabled (dev/test)
		} else {
			return fmt.Errorf("%s must use https:// scheme, got: %s", urlKey, parsed.Scheme)
		}
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", urlKey)
	}
	return nil
}

// ValidateStringField validates that a config field, if present, is a string.
func ValidateStringField(conf map[string]any, key string) error {
	if v, ok := conf[key]; ok {
		if _, ok := v.(string); !ok {
			return fmt.Errorf("%s must be a string", key)
		}
	}
	return nil
}

// ValidateCommonConfig validates the fields common to all providers:
// max_body_size, timeout, auto_auth_path, and default_role.
func ValidateCommonConfig(conf map[string]any) error {
	if err := ValidateMaxBodySize(conf); err != nil {
		return err
	}
	if err := ValidateTimeout(conf); err != nil {
		return err
	}
	if err := ValidateStringField(conf, "auto_auth_path"); err != nil {
		return err
	}
	return ValidateStringField(conf, "default_role")
}

// ValidateUserAuthConfig validates the secondary (user) transparent-auth config
// field user_auth_path. The bearer-format requirement on the referenced mount
// (the user leg cannot carry an X.509 client certificate) is enforced at
// runtime, where mount visibility exists — config validation here has none.
//
// It validates a mount config both when the mount is enabled and each time it
// is loaded, so it tolerates keys an existing mount may still carry: a
// pre-0.20 user_token_header is ignored (the user credential now always rides
// Authorization), and the removed user_auth_role is left for the provider to
// fail closed on (HasUserAuthRole); a config write refuses it
// (RefuseUserAuthRole).
func ValidateUserAuthConfig(conf map[string]any) error {
	return ValidateStringField(conf, "user_auth_path")
}

// userAuthRoleKey is the provider config key that named the auth role a user
// credential was admitted under. It was removed: a user is admitted with no
// role, and its token's audience is bound by the user auth mount or by the
// provider's resource identifier.
const userAuthRoleKey = "user_auth_role"

// ErrUserAuthRoleRemoved is why a provider whose stored configuration still
// names user_auth_role refuses every user credential: the setting bound the
// user token's audience through the role, and nothing it named is consulted
// any more.
var ErrUserAuthRoleRemoved = errors.New("user_auth_role was removed: the token audience is now bound by " +
	"the user auth mount's bound_audiences, or by this mount's resource identifier; remove user_auth_role to continue")

// HasUserAuthRole reports whether conf, a provider configuration as stored or
// as given when the mount was enabled, still names user_auth_role.
func HasUserAuthRole(conf map[string]any) bool {
	role, _ := conf[userAuthRoleKey].(string)
	return role != ""
}

// StoredUserAuthRole reports whether a stored provider configuration entry
// still names user_auth_role. A nil entry names nothing.
func StoredUserAuthRole(entry *sdklogical.StorageEntry) bool {
	if entry == nil {
		return false
	}
	var stored struct {
		UserAuthRole string `json:"user_auth_role"`
	}
	if err := entry.DecodeJSON(&stored); err != nil {
		return false
	}
	return stored.UserAuthRole != ""
}

// RefuseUserAuthRole refuses a provider config write that names
// user_auth_role, with a 400. An empty value names no role and passes.
func RefuseUserAuthRole(raw map[string]any) error {
	v, ok := raw[userAuthRoleKey]
	if !ok || v == nil {
		return nil
	}
	if s, isString := v.(string); isString && s == "" {
		return nil
	}
	return logical.ErrBadRequest(ErrUserAuthRoleRemoved.Error())
}
