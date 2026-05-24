package helpers

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// NormalizeSingleDashFlags rewrites Vault-style single-dash long flags
// (e.g. -format=json) to Cobra-style double-dash long flags
// (--format=json) so operators migrating from Vault don't trip on the
// muscle-memory difference. pflag is POSIX-strict and treats `-format`
// as `-f` taking value `ormat=json` — see cobra#2192 (closed wontfix).
//
// Short flags, the `--` terminator, and tokens whose name doesn't match
// a registered long flag pass through unchanged so pflag's existing
// error paths still run on genuine typos.
func NormalizeSingleDashFlags(root *cobra.Command, args []string) []string {
	if len(args) == 0 {
		return args
	}
	// Don't touch cobra's shell-completion subcommands — they have their
	// own internal arg format (e.g. partial flag fragments mid-typing)
	// that we must not rewrite.
	if args[0] == "__complete" || args[0] == "__completeNoDesc" {
		return args
	}

	longFlags := collectLongFlagNames(root)

	out := make([]string, 0, len(args))
	afterTerminator := false
	for _, arg := range args {
		if afterTerminator {
			out = append(out, arg)
			continue
		}
		if arg == "--" {
			afterTerminator = true
			out = append(out, arg)
			continue
		}
		if len(arg) < 2 || arg[0] != '-' || arg == "-" || strings.HasPrefix(arg, "--") {
			out = append(out, arg)
			continue
		}

		rest := arg[1:]
		name, _, _ := strings.Cut(rest, "=")
		if longFlags[name] {
			out = append(out, "--"+rest)
		} else {
			out = append(out, arg)
		}
	}
	return out
}

func collectLongFlagNames(cmd *cobra.Command) map[string]bool {
	// Cobra auto-adds --help and --version per command lazily during
	// Execute(); they aren't always in the flagsets at preprocessing
	// time, so seed them explicitly.
	//
	// NOTE: if any subtree ever calls Flags().SetNormalizeFunc, the
	// canonical name pflag returns from VisitAll may differ from the
	// literal token the user typed (e.g. dry_run → dry-run). The lookup
	// below would miss the user's form. The codebase doesn't use
	// SetNormalizeFunc today; if that changes, apply the same
	// normalizer to `name` before the map lookup in
	// NormalizeSingleDashFlags.
	names := map[string]bool{"help": true, "version": true}
	visit := func(f *pflag.Flag) { names[f.Name] = true }
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		// Cobra merges PersistentFlags into c.Flags() lazily at parse
		// time, so we must visit both sets explicitly to catch
		// persistents declared at this command.
		c.PersistentFlags().VisitAll(visit)
		c.Flags().VisitAll(visit)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(cmd)
	return names
}
