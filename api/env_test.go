package api

import (
	"os"
	"testing"
)

func TestReadWardenVariable(t *testing.T) {
	t.Run("valid prefix", func(t *testing.T) {
		os.Setenv("WARDEN_TEST_VAR", "hello")
		defer os.Unsetenv("WARDEN_TEST_VAR")

		val := ReadWardenVariable("WARDEN_TEST_VAR")
		if val != "hello" {
			t.Errorf("expected hello, got %q", val)
		}
	})

	t.Run("missing prefix", func(t *testing.T) {
		os.Setenv("OTHER_VAR", "world")
		defer os.Unsetenv("OTHER_VAR")

		val := ReadWardenVariable("OTHER_VAR")
		if val != "" {
			t.Errorf("expected empty, got %q", val)
		}
	})

	t.Run("unset variable", func(t *testing.T) {
		val := ReadWardenVariable("WARDEN_NONEXISTENT")
		if val != "" {
			t.Errorf("expected empty, got %q", val)
		}
	})
}
