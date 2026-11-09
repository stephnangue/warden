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

// parseSAUsername splits as the API server does: exactly two parts after the
// prefix, a DNS-1123 label namespace and a DNS-1123 subdomain name.
func TestParseSAUsername_LikeTheAPIServer(t *testing.T) {
	long := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = 'a'
		}
		return string(b)
	}
	accepted := []struct{ username, ns, name string }{
		{"system:serviceaccount:default:my.app-1", "default", "my.app-1"},
		{"system:serviceaccount:0ns:0", "0ns", "0"},
		{"system:serviceaccount:" + long(63) + ":" + long(253), long(63), long(253)},
		// Only the subdomain as a whole is bounded, as in the API server.
		{"system:serviceaccount:ns:" + long(100) + ".b", "ns", long(100) + ".b"},
	}
	for _, tc := range accepted {
		ns, name, ok := parseSAUsername(tc.username)
		if !ok || ns != tc.ns || name != tc.name {
			t.Errorf("%q: got ns=%q name=%q ok=%v", tc.username, ns, name, ok)
		}
	}
	refused := []string{
		"system:serviceaccount:ns:name:extra",
		"system:serviceaccount:ns::",
		"system:serviceaccount::",
		"system:serviceaccount:",
		"system:serviceaccount:Default:myapp",
		"system:serviceaccount:default:MyApp",
		"system:serviceaccount:my.ns:myapp", // a namespace is a label, no dots
		"system:serviceaccount:-ns:myapp",
		"system:serviceaccount:ns-:myapp",
		"system:serviceaccount:ns:app-",
		"system:serviceaccount:ns:.app",
		"system:serviceaccount:ns:a..b",
		"system:serviceaccount:ns:my_app",
		"system:serviceaccount:" + long(64) + ":myapp",
		"system:serviceaccount:ns:" + long(254),
		"system:serviceaccounts:default:myapp",
		"system:node:worker-1",
		"oidc:alice@example.com",
	}
	for _, username := range refused {
		if ns, name, ok := parseSAUsername(username); ok || ns != "" || name != "" {
			t.Errorf("%q: got ns=%q name=%q ok=%v, want refused", username, ns, name, ok)
		}
	}
}
