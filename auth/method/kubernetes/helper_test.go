package kubernetes

import "testing"

func TestParseSAUsername(t *testing.T) {
	t.Run("valid SA username", func(t *testing.T) {
		ns, name, ok := parseSAUsername("system:serviceaccount:default:myapp")
		if !ok || ns != "default" || name != "myapp" {
			t.Fatalf("got ns=%q name=%q ok=%v", ns, name, ok)
		}
	})
	t.Run("namespace with hyphens", func(t *testing.T) {
		ns, name, ok := parseSAUsername("system:serviceaccount:kube-system:coredns")
		if !ok || ns != "kube-system" || name != "coredns" {
			t.Fatalf("got ns=%q name=%q ok=%v", ns, name, ok)
		}
	})
	t.Run("missing prefix", func(t *testing.T) {
		if _, _, ok := parseSAUsername("system:anonymous"); ok {
			t.Fatal("should reject non-SA username")
		}
	})
	t.Run("missing namespace", func(t *testing.T) {
		if _, _, ok := parseSAUsername("system:serviceaccount::myapp"); ok {
			t.Fatal("should reject empty namespace")
		}
	})
	t.Run("missing name", func(t *testing.T) {
		if _, _, ok := parseSAUsername("system:serviceaccount:default:"); ok {
			t.Fatal("should reject empty name")
		}
	})
	t.Run("missing colon between ns and name", func(t *testing.T) {
		if _, _, ok := parseSAUsername("system:serviceaccount:default"); ok {
			t.Fatal("should reject malformed (no second colon)")
		}
	})
	t.Run("empty string", func(t *testing.T) {
		if _, _, ok := parseSAUsername(""); ok {
			t.Fatal("should reject empty input")
		}
	})
}

func TestMatchBoundList(t *testing.T) {
	t.Run("empty list rejects", func(t *testing.T) {
		if matchBoundList(nil, "anything") {
			t.Fatal("empty list must reject")
		}
	})
	t.Run("exact match", func(t *testing.T) {
		if !matchBoundList([]string{"a", "b"}, "b") {
			t.Fatal("expected exact match")
		}
	})
	t.Run("wildcard matches any", func(t *testing.T) {
		if !matchBoundList([]string{"*"}, "anything") {
			t.Fatal("wildcard should match")
		}
	})
	t.Run("no match", func(t *testing.T) {
		if matchBoundList([]string{"a", "b"}, "c") {
			t.Fatal("no element should match")
		}
	})
}

func TestMatchRoleBindings(t *testing.T) {
	role := &KubernetesRole{
		BoundServiceAccountNamespaces: []string{"default", "prod"},
		BoundServiceAccountNames:      []string{"myapp"},
	}
	t.Run("matches", func(t *testing.T) {
		if err := matchRoleBindings(role, "default", "myapp"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("namespace mismatch", func(t *testing.T) {
		if err := matchRoleBindings(role, "other", "myapp"); err == nil {
			t.Fatal("expected namespace mismatch error")
		}
	})
	t.Run("name mismatch", func(t *testing.T) {
		if err := matchRoleBindings(role, "default", "otherapp"); err == nil {
			t.Fatal("expected name mismatch error")
		}
	})
	t.Run("wildcard namespace allows any", func(t *testing.T) {
		r := &KubernetesRole{
			BoundServiceAccountNamespaces: []string{"*"},
			BoundServiceAccountNames:      []string{"myapp"},
		}
		if err := matchRoleBindings(r, "anywhere", "myapp"); err != nil {
			t.Fatalf("wildcard ns should accept any namespace: %v", err)
		}
	})
}

func TestAudienceMatches(t *testing.T) {
	t.Run("empty want matches anything (no audience binding)", func(t *testing.T) {
		if !audienceMatches("", nil) {
			t.Fatal("empty want should match")
		}
		if !audienceMatches("", []string{"x"}) {
			t.Fatal("empty want should match even with audiences present")
		}
	})
	t.Run("want present in got", func(t *testing.T) {
		if !audienceMatches("api", []string{"api", "internal"}) {
			t.Fatal("want should match when present")
		}
	})
	t.Run("want not present in got", func(t *testing.T) {
		if audienceMatches("api", []string{"internal"}) {
			t.Fatal("want should not match when absent")
		}
	})
	t.Run("want present but got is empty", func(t *testing.T) {
		if audienceMatches("api", nil) {
			t.Fatal("want should not match against empty audiences")
		}
	})
}

func TestOnlyWildcardOrEmpty(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		if !onlyWildcardOrEmpty(nil) {
			t.Fatal("empty should return true")
		}
	})
	t.Run("only wildcard", func(t *testing.T) {
		if !onlyWildcardOrEmpty([]string{"*"}) {
			t.Fatal("only wildcard should return true")
		}
	})
	t.Run("multiple wildcards (degenerate)", func(t *testing.T) {
		if !onlyWildcardOrEmpty([]string{"*", "*"}) {
			t.Fatal("all wildcards should return true")
		}
	})
	t.Run("has concrete value", func(t *testing.T) {
		if onlyWildcardOrEmpty([]string{"myapp"}) {
			t.Fatal("concrete value should return false")
		}
		if onlyWildcardOrEmpty([]string{"*", "myapp"}) {
			t.Fatal("wildcard+concrete should return false")
		}
	})
}
