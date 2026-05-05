package helpers

import (
	"bytes"
	"strings"
	"testing"
)

func TestResolveDryRun_FlagWins(t *testing.T) {
	t.Cleanup(func() { SetDryRun(false) })
	SetDryRun(true)
	if !ResolveDryRun() {
		t.Fatal("ResolveDryRun() = false; want true when --dry-run is set")
	}
}

func TestResolveDryRun_EnvVarTriggers(t *testing.T) {
	t.Cleanup(func() { SetDryRun(false) })
	cases := []struct {
		env  string
		want bool
	}{
		{"", false},
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"1", true},
		{"yes", true},
		{"on", true},
		{"0", false},
		{"false", false},
		{"no", false},
		{"off", false},
	}
	for _, tt := range cases {
		t.Run(tt.env, func(t *testing.T) {
			t.Setenv("WARDEN_DRY_RUN", tt.env)
			if got := ResolveDryRun(); got != tt.want {
				t.Errorf("ResolveDryRun() with WARDEN_DRY_RUN=%q = %v; want %v", tt.env, got, tt.want)
			}
		})
	}
}

func TestResolveDryRun_FlagOverridesUnsetEnv(t *testing.T) {
	t.Cleanup(func() { SetDryRun(false) })
	t.Setenv("WARDEN_DRY_RUN", "")
	SetDryRun(true)
	if !ResolveDryRun() {
		t.Fatal("flag should win when env is empty")
	}
}

func TestEmitDryRunWarning_OncePerProcess(t *testing.T) {
	stderr := &bytes.Buffer{}
	SetErrorWriter(stderr)
	t.Cleanup(ResetWriters)
	t.Cleanup(ResetDryRunWarning)
	ResetDryRunWarning()

	EmitDryRunWarning()
	EmitDryRunWarning()
	EmitDryRunWarning()

	got := stderr.String()
	count := strings.Count(got, "X-Warden-Dry-Run")
	if count != 1 {
		t.Fatalf("expected exactly one warning emission across multiple calls; got %d. Output:\n%s", count, got)
	}
	if !strings.Contains(got, "server enforcement hasn't shipped") {
		t.Errorf("warning should mention enforcement gap; got: %s", got)
	}
}

func TestEmitDryRunWarning_GoesToStderrNotStdout(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	SetOutputWriter(stdout)
	SetErrorWriter(stderr)
	t.Cleanup(ResetWriters)
	t.Cleanup(ResetDryRunWarning)
	ResetDryRunWarning()

	EmitDryRunWarning()

	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty so JSON consumers stay clean; got: %s", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("expected warning on stderr; got empty")
	}
}
