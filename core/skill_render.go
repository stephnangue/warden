package core

import (
	"bytes"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// skillFrontmatter is the frontmatter of a SKILL.md as the discovery server
// serves it: the Agent Skills fields at the top level and Warden's own fields
// under metadata, which the Agent Skills specification defines as a map of
// string to string. The same value is rendered into the file and returned as
// the skill's frontmatter object, so the two always match.
type skillFrontmatter struct {
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// frontmatterFor projects a stored skill onto the served frontmatter.
func frontmatterFor(s *Skill) skillFrontmatter {
	meta := make(map[string]string, 4)
	for k, v := range map[string]string{
		"category": s.Category,
		"provider": s.Provider,
		"upstream": s.Upstream,
		"requires": strings.Join(s.Requires, " "),
	} {
		if v != "" {
			meta[k] = v
		}
	}
	if len(meta) == 0 {
		meta = nil
	}
	return skillFrontmatter{Name: s.Name, Description: s.Description, Metadata: meta}
}

// renderSkillMarkdown renders a stored skill as the SKILL.md the discovery
// server serves: YAML frontmatter followed by the body. The YAML encoder
// emits struct fields in order and map keys sorted, and does not wrap long
// lines, so the output is byte-for-byte stable for a given skill.
func renderSkillMarkdown(s *Skill) ([]byte, error) {
	front, err := yaml.Marshal(frontmatterFor(s))
	if err != nil {
		return nil, fmt.Errorf("render frontmatter of skill %q: %w", s.Name, err)
	}
	var b bytes.Buffer
	b.WriteString("---\n")
	b.Write(front)
	b.WriteString("---\n\n")
	b.WriteString(s.Body)
	return b.Bytes(), nil
}
