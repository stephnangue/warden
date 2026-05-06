package helpers

import "testing"

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
