package githttp

import (
	"fmt"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// gitMaxBodySizeKey is the config field and state key holding the per-mount
// override for the Git request body cap.
const gitMaxBodySizeKey = "git_max_body_size"

// MaxBodySizeField returns the framework.FieldSchema for the
// git_max_body_size config field. Providers spread this into their
// ProviderSpec.ExtraConfigFields under the gitMaxBodySizeKey.
func MaxBodySizeField() *framework.FieldSchema {
	return &framework.FieldSchema{
		Type:        framework.TypeInt64,
		Description: "Maximum request body size for Git smart-HTTP requests in bytes (default: 2 GiB, min: 1 MiB, max: 10 GiB)",
		Default:     DefaultMaxBodySize,
	}
}

// ReadMaxBodySize returns the git_max_body_size value from state, applying
// the default when unset or non-positive. Providers call this from
// ProviderSpec.OnConfigRead to surface the field in config-read responses.
func ReadMaxBodySize(state map[string]any) int64 {
	size, _ := state[gitMaxBodySizeKey].(int64)
	if size <= 0 {
		size = DefaultMaxBodySize
	}
	return size
}

// WriteMaxBodySize validates the incoming git_max_body_size from a config
// write and stores the accepted value in state. Returns an error when the
// supplied value is out of bounds; state is not modified in that case.
// Providers call this from ProviderSpec.OnConfigWrite. When the field is
// not present in the write payload, this is a no-op.
func WriteMaxBodySize(d *framework.FieldData, state map[string]any) error {
	val, ok := d.GetOk(gitMaxBodySizeKey)
	if !ok {
		return nil
	}
	size, ok := val.(int64)
	if !ok {
		return fmt.Errorf("%s must be an integer", gitMaxBodySizeKey)
	}
	if size < MinMaxBodySize {
		return fmt.Errorf("%s must be at least %d bytes (1 MiB)", gitMaxBodySizeKey, MinMaxBodySize)
	}
	if size > MaxMaxBodySize {
		return fmt.Errorf("%s must not exceed %d bytes (10 GiB)", gitMaxBodySizeKey, MaxMaxBodySize)
	}
	state[gitMaxBodySizeKey] = size
	return nil
}

// InitializeMaxBodySize loads the git_max_body_size from persisted config
// into state. Providers call this from ProviderSpec.OnInitialize. Falls
// back to the default when the persisted value is missing or coerces to a
// non-positive number.
func InitializeMaxBodySize(config map[string]any, state map[string]any) {
	if size, ok := httpproxy.ReadInt64Config(config[gitMaxBodySizeKey]); ok {
		state[gitMaxBodySizeKey] = size
		return
	}
	state[gitMaxBodySizeKey] = DefaultMaxBodySize
}
