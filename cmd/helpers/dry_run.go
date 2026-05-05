package helpers

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// Persistent --dry-run flag value, populated by cmd/warden.go via the pointer
// accessor. Read once per command invocation through ResolveDryRun.
var dryRunFlag bool

// DryRunFlagPtr exposes the persistent flag for cobra binding.
func DryRunFlagPtr() *bool { return &dryRunFlag }

// SetDryRun overrides the dry-run state. Intended for tests.
func SetDryRun(v bool) { dryRunFlag = v }

// ResolveDryRun returns true when the user has requested dry-run mode via
// the --dry-run flag or the WARDEN_DRY_RUN env var. Any value of
// WARDEN_DRY_RUN other than "" / "0" / "false" / "no" / "off" (case
// insensitive) is treated as true.
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

// dryRunWarningOnce keeps the warning to a single emission per process so a
// command that makes multiple HTTP calls (e.g. a future `warden cred source
// create` that does a GET-then-PUT) doesn't spam the user.
var dryRunWarningOnce sync.Once

// EmitDryRunWarning writes the no-server-enforcement notice to stderr the
// first time it is called. Subsequent calls are no-ops. Wired from
// helpers.Client(); callers should not invoke it directly.
//
// The warning is emitted even in JSON modes so agents discover the gap —
// stderr stays out of stdout so the structured payload remains parseable.
// Once server-side enforcement (PR 7) ships, this warning will be replaced
// with response-shape verification.
func EmitDryRunWarning() {
	dryRunWarningOnce.Do(func() {
		fmt.Fprintln(errWriter,
			"warning: --dry-run sends X-Warden-Dry-Run but server enforcement hasn't shipped yet; the request WILL be processed normally")
	})
}

// ResetDryRunWarning re-arms the once for tests.
func ResetDryRunWarning() {
	dryRunWarningOnce = sync.Once{}
}
