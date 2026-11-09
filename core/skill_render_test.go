package core

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// splitRendered parses a rendered SKILL.md the way a host reading it would and
// returns its frontmatter and body.
func splitRendered(t *testing.T, md []byte) (map[string]any, string) {
	t.Helper()
	require.True(t, bytes.HasPrefix(md, []byte("---\n")))
	front, body, ok := bytes.Cut(md[len("---\n"):], []byte("\n---\n\n"))
	require.True(t, ok, "no closing frontmatter delimiter in %q", md)
	var fm map[string]any
	require.NoError(t, yaml.Unmarshal(front, &fm))
	return fm, string(body)
}

// asJSONMap renders v the way the frontmatter object goes over the wire.
func asJSONMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

// The frontmatter a host parses out of the served file equals the frontmatter
// object served alongside it, field for field — the Skills extension treats a
// mismatch as a verification failure — including for text YAML could misread
// and lines long enough that a wrapping emitter would fold them.
func TestRenderSkillMarkdown_FrontmatterRoundTrips(t *testing.T) {
	skills := []*Skill{
		{
			Name:        "vault",
			Description: "Call HashiCorp Vault / OpenBao through Warden — read secrets, sign: encrypt # not a comment",
			Category:    SkillCategoryProviderGuide,
			Provider:    "vault",
			Upstream:    "HashiCorp Vault / OpenBao",
			Requires:    []string{"troubleshooting", "agent-flow"},
			Body:        "# Vault\n\n---\nnot frontmatter\n",
		},
		{
			Name:        "quirky",
			Description: `"quoted", 'single', \backslash, <html> & yes: no` + strings.Repeat(" long", 40),
			Category:    SkillCategoryCustom,
			Body:        "body",
		},
		{Name: "yes", Description: "true", Category: SkillCategoryCustom, Upstream: "1.0", Body: "b"},
		{Name: "unicode", Description: "naïve café — 日本語 🚀\ttab", Category: SkillCategoryShared},
	}
	for _, s := range skills {
		t.Run(s.Name, func(t *testing.T) {
			md, err := renderSkillMarkdown(s)
			require.NoError(t, err)
			fm, body := splitRendered(t, md)
			assert.Equal(t, asJSONMap(t, frontmatterFor(s)), fm)
			assert.Equal(t, s.Body, body)

			// One line per field: name, description, and metadata with one
			// line per key. A wrapped value would add continuation lines.
			want := 2
			if n := len(frontmatterFor(s).Metadata); n > 0 {
				want += 1 + n
			}
			front, _, _ := bytes.Cut(md[len("---\n"):], []byte("---\n"))
			assert.Equal(t, want, bytes.Count(front, []byte("\n")), "frontmatter:\n%s", front)
		})
	}
}

func TestFrontmatterFor_MetadataLayout(t *testing.T) {
	fm := frontmatterFor(&Skill{
		Name: "mcp-aws", Description: "d", Category: SkillCategoryProviderGuide,
		Provider: "mcp_aws", Requires: []string{"a", "b"},
	})
	assert.Equal(t, skillFrontmatter{
		Name:        "mcp-aws",
		Description: "d",
		Metadata: map[string]string{
			"category": "provider-guide",
			"provider": "mcp_aws",
			"requires": "skill://a/SKILL.md skill://b/SKILL.md",
		},
	}, fm)

	// Rendering is byte-for-byte stable, so a digest over it is too.
	s := &Skill{Name: "x", Description: "d", Category: SkillCategoryCustom, Provider: "p", Upstream: "u", Body: "b"}
	first, err := renderSkillMarkdown(s)
	require.NoError(t, err)
	for range 5 {
		again, err := renderSkillMarkdown(s)
		require.NoError(t, err)
		assert.Equal(t, first, again)
	}
	assert.Equal(t, "---\nname: x\ndescription: d\nmetadata:\n    category: custom\n    provider: p\n    upstream: u\n---\n\nb",
		string(first))
}
