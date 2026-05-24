package helpers

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

func newTestTree() *cobra.Command {
	root := &cobra.Command{Use: "warden"}
	var ns, output string
	var dryRun bool
	root.PersistentFlags().StringVarP(&ns, "namespace", "n", "", "")
	root.PersistentFlags().StringVarP(&output, "output", "o", "", "")
	root.PersistentFlags().BoolVarP(&dryRun, "dry-run", "D", false, "")

	auth := &cobra.Command{Use: "auth"}
	enable := &cobra.Command{Use: "enable"}
	var typeFlag, pathFlag string
	enable.Flags().StringVar(&typeFlag, "type", "", "")
	enable.Flags().StringVar(&pathFlag, "path", "", "")
	auth.AddCommand(enable)
	root.AddCommand(auth)

	operator := &cobra.Command{Use: "operator"}
	initCmd := &cobra.Command{Use: "init"}
	var format string
	initCmd.Flags().StringVar(&format, "format", "", "")
	operator.AddCommand(initCmd)
	root.AddCommand(operator)

	return root
}

func TestNormalizeSingleDashFlags(t *testing.T) {
	root := newTestTree()

	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "empty",
			in:   nil,
			want: nil,
		},
		{
			name: "double-dash long flag unchanged",
			in:   []string{"operator", "init", "--format=json"},
			want: []string{"operator", "init", "--format=json"},
		},
		{
			name: "single-dash long flag with equals rewritten",
			in:   []string{"operator", "init", "-format=json"},
			want: []string{"operator", "init", "--format=json"},
		},
		{
			name: "single-dash long flag space-separated rewritten",
			in:   []string{"-namespace", "ns1", "auth", "enable"},
			want: []string{"--namespace", "ns1", "auth", "enable"},
		},
		{
			name: "short flag preserved",
			in:   []string{"-n", "ns1", "auth", "enable"},
			want: []string{"-n", "ns1", "auth", "enable"},
		},
		{
			name: "bundled shorthand unknown long flag preserved",
			in:   []string{"-no", "ns1"},
			want: []string{"-no", "ns1"},
		},
		{
			name: "subcommand-only long flag rewritten",
			in:   []string{"auth", "enable", "-type=jwt", "jwt-X"},
			want: []string{"auth", "enable", "--type=jwt", "jwt-X"},
		},
		{
			name: "double-dash terminator stops rewriting",
			in:   []string{"auth", "enable", "--", "-format=json"},
			want: []string{"auth", "enable", "--", "-format=json"},
		},
		{
			name: "single dash alone preserved",
			in:   []string{"-"},
			want: []string{"-"},
		},
		{
			name: "single-dash unknown long flag preserved",
			in:   []string{"-totallyunknown"},
			want: []string{"-totallyunknown"},
		},
		{
			name: "single-dash bool long flag rewritten",
			in:   []string{"-dry-run", "auth", "list"},
			want: []string{"--dry-run", "auth", "list"},
		},
		{
			name: "short flag bundled with equals value preserved",
			in:   []string{"-n=ns1"},
			want: []string{"-n=ns1"},
		},
		{
			name: "multiple flags interspersed",
			in:   []string{"-namespace", "ns1", "auth", "enable", "-type=jwt", "-path=jwt-X"},
			want: []string{"--namespace", "ns1", "auth", "enable", "--type=jwt", "--path=jwt-X"},
		},
		{
			// Cobra adds --help lazily per command; we seed "help" in
			// the map explicitly so single-dash usage always works.
			name: "single-dash help rewritten",
			in:   []string{"-help"},
			want: []string{"--help"},
		},
		{
			name: "single-dash version rewritten",
			in:   []string{"-version"},
			want: []string{"--version"},
		},
		{
			// Cobra shell-completion subcommands have their own arg
			// format (partial fragments mid-typing); we must not
			// rewrite them.
			name: "__complete short-circuited",
			in:   []string{"__complete", "auth", "-form"},
			want: []string{"__complete", "auth", "-form"},
		},
		{
			name: "__completeNoDesc short-circuited",
			in:   []string{"__completeNoDesc", "auth", "-form"},
			want: []string{"__completeNoDesc", "auth", "-form"},
		},
		{
			// Negative numeric value following a short flag: -5 isn't
			// a registered long flag name, so passes through.
			name: "negative numeric value passes through",
			in:   []string{"-n", "-5"},
			want: []string{"-n", "-5"},
		},
		{
			// Known limitation: we don't track "previous flag expects
			// a value", so a value that itself names a long flag is
			// rewritten. pflag then errors loudly (flag needs value,
			// can't consume another flag), so it's not silent
			// corruption. Vault users with dash-prefixed values should
			// use the -key=value form or the -- terminator.
			name: "value-that-names-a-flag is rewritten (known limitation)",
			in:   []string{"-output", "-format=json"},
			want: []string{"--output", "--format=json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeSingleDashFlags(root, tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("NormalizeSingleDashFlags(%v) = %v; want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeSingleDashFlags_DoesNotMutateInput(t *testing.T) {
	root := newTestTree()
	in := []string{"-namespace", "ns1", "auth", "enable"}
	original := append([]string{}, in...)
	_ = NormalizeSingleDashFlags(root, in)
	if !reflect.DeepEqual(in, original) {
		t.Errorf("input slice was mutated: got %v, want %v", in, original)
	}
}
