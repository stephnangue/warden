package core

import (
	"bufio"
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
)

//go:embed seed/skills/*.md
var skillSeedFS embed.FS

const (
	// seededMarkerKey records that the foundation seed has run against
	// this barrier view at least once. Once set, SeedFoundation is a
	// no-op — operator deletions of seed-origin skills are respected
	// across restarts.
	seededMarkerKey = "_meta/seeded"
)

// SeedProviderSkill installs a provider-type skill into the registry,
// idempotently. Called by the provider-mount handler with the markdown
// shipped alongside the provider's Go code.
//
// providerType is the mount type the caller is registering (e.g., "aws").
// The frontmatter's `name` field MUST equal providerType — this guards
// against wiring errors where a provider's skill markdown gets mapped to
// the wrong type in CoreConfig.ProviderSkills.
//
// Behavior:
//   - If the skill name already exists (operator edit OR previous mount
//     of the same type), this is a no-op. The operator's edits are
//     preserved.
//   - If the name is absent (never seeded, or operator deleted), the
//     markdown is parsed and persisted with Origin="seed".
//   - A bad markdown payload OR name/type mismatch returns an error so
//     the caller can log; the mount itself must not fail because of a
//     skill error.
//
// Unlike SeedFoundation, this method does not use a marker — each
// provider type carries its own existence check via the registry.
func (s *SkillStore) SeedProviderSkill(ctx context.Context, providerType, markdown string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrSkillStoreClosed
	}
	if s.storage == nil {
		return errors.New("skill store storage not initialized")
	}

	skill, err := parseSkillMarkdown([]byte(markdown))
	if err != nil {
		return fmt.Errorf("parse provider skill: %w", err)
	}
	if skill.Name != providerType {
		return fmt.Errorf("provider skill name %q does not match provider type %q (likely a wiring error in CoreConfig.ProviderSkills)", skill.Name, providerType)
	}
	return s.seedOne(ctx, skill)
}

// SeedFoundation writes the embedded foundation skills (discovery,
// foundation, troubleshooting) into the registry on first call.
// Subsequent calls are no-ops thanks to the seeded marker. Operator
// deletions of seeded skills are not reverted.
//
// Provider-type skills follow a different lifecycle (seeded at provider
// mount time, see SeedProviderSkill) and are intentionally not handled
// here.
func (s *SkillStore) SeedFoundation(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrSkillStoreClosed
	}
	if s.storage == nil {
		return errors.New("skill store storage not initialized")
	}

	marker, err := s.storage.Get(ctx, seededMarkerKey)
	if err != nil {
		return fmt.Errorf("read seeded marker: %w", err)
	}
	if marker != nil {
		s.logger.Debug("foundation skills already seeded; skipping")
		return nil
	}

	skills, err := loadEmbeddedFoundationSkills()
	if err != nil {
		return fmt.Errorf("load embedded foundation skills: %w", err)
	}

	for _, skill := range skills {
		if err := s.seedOne(ctx, skill); err != nil {
			return fmt.Errorf("seed %q: %w", skill.Name, err)
		}
	}

	if err := s.storage.Put(ctx, &sdklogical.StorageEntry{
		Key:   seededMarkerKey,
		Value: []byte("1"),
	}); err != nil {
		return fmt.Errorf("write seeded marker: %w", err)
	}

	s.logger.Info("foundation skills seeded", logger.Int("count", len(skills)))
	return nil
}

// seedOne persists a single skill with Origin="seed". Idempotent within
// a single seed call: if the name already exists, leaves the existing
// record alone. Caller holds the write lock.
func (s *SkillStore) seedOne(ctx context.Context, skill *Skill) error {
	existing, err := s.load(ctx, skill.Name)
	if err != nil && !errors.Is(err, ErrSkillNotFound) {
		return err
	}
	if existing != nil {
		return nil
	}
	// Set Origin before validation so any future origin-aware checks in
	// validateSkill see the final value rather than the parser default.
	skill.Origin = SkillOriginSeed
	if err := validateSkill(skill); err != nil {
		return err
	}
	now := time.Now()
	skill.CreatedAt = now
	skill.UpdatedAt = now
	skill.Version = 1
	return s.persist(ctx, skill)
}

// loadEmbeddedFoundationSkills parses every markdown file embedded at
// seed/skills/*.md (excluding subdirectories) into Skill records.
func loadEmbeddedFoundationSkills() ([]*Skill, error) {
	entries, err := fs.ReadDir(skillSeedFS, "seed/skills")
	if err != nil {
		return nil, fmt.Errorf("read embed dir: %w", err)
	}
	var skills []*Skill
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		fpath := path.Join("seed/skills", entry.Name())
		raw, err := fs.ReadFile(skillSeedFS, fpath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", fpath, err)
		}
		skill, err := parseSkillMarkdown(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", fpath, err)
		}
		skills = append(skills, skill)
	}
	return skills, nil
}

// parseSkillMarkdown parses a markdown file with YAML-style frontmatter
// of the form:
//
//	---
//	name: discovery
//	description: "..."
//	category: agent-flow
//	requires: [foundation]
//	upstream: github.com/foo
//	---
//	<body>
//
// Only the subset of YAML actually used by warden skill files is
// supported: scalar string values (quoted or bare) and bracketed
// string lists. Comments, multi-line strings, and nested maps are not.
func parseSkillMarkdown(raw []byte) (*Skill, error) {
	front, body, err := splitFrontmatter(raw)
	if err != nil {
		return nil, err
	}
	skill, err := extractSkillFields(front)
	if err != nil {
		return nil, err
	}
	skill.Body = strings.TrimLeft(string(body), "\n")
	return skill, nil
}

// splitFrontmatter peels the YAML frontmatter off a markdown file. It
// expects the opening "---" on the first non-empty line and returns the
// frontmatter (between delimiters) and body (everything after the
// closing "---") as separate byte slices.
func splitFrontmatter(raw []byte) (front, body []byte, err error) {
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 64*1024), maxSkillBodyBytes+64*1024)

	if !scanner.Scan() {
		return nil, nil, fmt.Errorf("empty file")
	}
	if strings.TrimSpace(scanner.Text()) != "---" {
		return nil, nil, fmt.Errorf("missing opening frontmatter delimiter")
	}

	var frontBuf, bodyBuf strings.Builder
	inFront := true
	for scanner.Scan() {
		line := scanner.Text()
		if inFront && strings.TrimSpace(line) == "---" {
			inFront = false
			continue
		}
		if inFront {
			frontBuf.WriteString(line)
			frontBuf.WriteByte('\n')
		} else {
			bodyBuf.WriteString(line)
			bodyBuf.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan: %w", err)
	}
	if inFront {
		return nil, nil, fmt.Errorf("missing closing frontmatter delimiter")
	}
	return []byte(frontBuf.String()), []byte(bodyBuf.String()), nil
}

// extractSkillFields walks frontmatter lines and populates the recognized
// Skill fields. Unknown keys are tolerated (forward-compat).
func extractSkillFields(front []byte) (*Skill, error) {
	skill := &Skill{}
	scanner := bufio.NewScanner(strings.NewReader(string(front)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := splitKeyValue(line)
		if !ok {
			return nil, fmt.Errorf("malformed frontmatter line %q", line)
		}
		switch key {
		case "name":
			skill.Name = unquote(value)
		case "description":
			skill.Description = unquote(value)
		case "category":
			skill.Category = unquote(value)
		case "requires":
			skill.Requires = parseList(value)
		case "upstream":
			skill.Upstream = unquote(value)
		case "provider":
			skill.Provider = unquote(value)
		default:
			// Unknown keys are tolerated — forward-compat for future fields.
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan frontmatter: %w", err)
	}
	return skill, nil
}

func splitKeyValue(line string) (key, value string, ok bool) {
	idx := strings.IndexByte(line, ':')
	if idx <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

// unquote strips one matched pair of surrounding quotes (double or single).
func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// parseList parses a bracketed comma-separated list: "[a, b, "c d"]".
func parseList(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return nil
	}
	parts := strings.Split(inner, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := unquote(strings.TrimSpace(p))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
