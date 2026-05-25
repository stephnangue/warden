package helpers

import (
	"os"
	"strings"
)

// Persistent -dry-run flag value, populated by cmd/warden.go via the pointer
// accessor. Read once per command invocation through ResolveDryRun.
var dryRunFlag bool

// DryRunFlagPtr exposes the persistent flag for cobra binding.
func DryRunFlagPtr() *bool { return &dryRunFlag }

// SetDryRun overrides the dry-run state. Intended for tests.
func SetDryRun(v bool) { dryRunFlag = v }

// ResolveDryRun returns true when the user has requested dry-run mode via
// the -dry-run flag or the WARDEN_DRY_RUN env var. Any value of
// WARDEN_DRY_RUN other than "" / "0" / "false" / "no" / "off" (case
// insensitive) is treated as true.
//
// Dry-run is implemented locally — when the flag is set, mutating commands
// validate their payload against the server's schema (via the already-cached
// /v1/sys/schema endpoint) and short-circuit before making the HTTP call.
// Nothing is ever sent to the server, so there's no risk of side effects
// even with a buggy implementation.
func ResolveDryRun() bool {
	if dryRunFlag {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WARDEN_DRY_RUN"))) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}
