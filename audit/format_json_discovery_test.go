package audit

import (
	"context"
	"strings"
	"testing"
)

func discoveryEntry() *LogEntry {
	return &LogEntry{Auth: &Auth{
		PrincipalID: "agent-1",
		Discovery: &DiscoveryAuth{
			AdmittedBy:   []AdmittedMount{{Mount: "jwt/", PrincipalID: "agent-1"}, {Mount: "k8s/", PrincipalID: "agent-1"}},
			RolesGranted: 1,
		},
	}}
}

// Salting principal_id salts the principals a discovery request was admitted
// as too: they are the same identity, and left in clear they would undo it.
func TestJSONFormat_PrincipalSaltCoversDiscovery(t *testing.T) {
	f := NewJSONFormat(
		WithSaltFunc(func(_ context.Context, v string) (string, error) { return "hmac-sha256:" + strings.ToUpper(v), nil }),
		WithSaltFields([]string{"auth.principal_id"}),
	)
	out, err := f.FormatRequest(context.Background(), discoveryEntry())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"agent-1"`) {
		t.Errorf("a principal left in clear: %s", out)
	}
	if strings.Count(string(out), "hmac-sha256:AGENT-1") != 3 {
		t.Errorf("want the principal and both admitted principals salted: %s", out)
	}
}

// Omitting principal_id omits the admitted principals too; the mounts stay.
func TestJSONFormat_PrincipalOmitCoversDiscovery(t *testing.T) {
	f := NewJSONFormat(WithOmitFields([]string{"auth.principal_id"}))
	out, err := f.FormatRequest(context.Background(), discoveryEntry())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "agent-1") {
		t.Errorf("a principal left in: %s", out)
	}
	if !strings.Contains(string(out), `"mount":"jwt/"`) {
		t.Errorf("the admitting mounts are kept: %s", out)
	}
}
