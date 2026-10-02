package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

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

// renderedSkill is a skill's SKILL.md as the discovery server serves it, with
// the digest a Skills extension listing carries for it.
type renderedSkill struct {
	version   int
	updatedAt time.Time
	markdown  []byte
	digest    string // "sha256:<64 lowercase hex>"
}

// skillRenderCache memoises rendered SKILL.md bytes and their digests per
// skill name, so a skills/list does not re-render and re-hash every body on
// every call. An entry is reused only while the skill's version and update
// time still match; every write to a skill changes at least one of them, so
// an edited, renamed or recreated skill is re-rendered. The zero value is
// ready to use and safe for concurrent use.
type skillRenderCache struct {
	m sync.Map // skill name → *renderedSkill
}

// get returns s rendered, from the cache when it is still current.
func (c *skillRenderCache) get(s *Skill) (*renderedSkill, error) {
	if v, ok := c.m.Load(s.Name); ok {
		r := v.(*renderedSkill)
		if r.version == s.Version && r.updatedAt.Equal(s.UpdatedAt) {
			return r, nil
		}
	}
	md, err := renderSkillMarkdown(s)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(md)
	r := &renderedSkill{
		version:   s.Version,
		updatedAt: s.UpdatedAt,
		markdown:  md,
		digest:    "sha256:" + hex.EncodeToString(sum[:]),
	}
	c.m.Store(s.Name, r)
	return r, nil
}

// forget drops the entry for a skill that no longer exists under name.
func (c *skillRenderCache) forget(name string) {
	c.m.Delete(name)
}

// reset drops every entry.
func (c *skillRenderCache) reset() {
	c.m.Clear()
}
