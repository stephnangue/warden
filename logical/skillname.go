package logical

import (
	"regexp"
	"strings"
)

// MaxSkillNameLen is the longest skill name accepted, per the Agent Skills
// specification.
const MaxSkillNameLen = 64

// skillNameRegex is the Agent Skills naming rule: lowercase letters and
// digits, separated by single hyphens, never leading or trailing. Skill
// names appear as the final segment of a skill:// URI and as the `name`
// field of a served SKILL.md, so they must satisfy it exactly.
var skillNameRegex = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// SkillNameRule is a human-readable statement of the rule enforced by
// ValidSkillName, for error messages.
const SkillNameRule = "lowercase letters, digits and single hyphens only, no leading or trailing hyphen (max 64)"

// ValidSkillName reports whether name satisfies the Agent Skills naming rule.
func ValidSkillName(name string) bool {
	return len(name) <= MaxSkillNameLen && skillNameRegex.MatchString(name)
}

// SkillNameForProvider returns the name of the skill shipped with a provider
// type. Provider types may contain underscores (mcp_aws), which skill names
// may not, so underscores become hyphens.
func SkillNameForProvider(providerType string) string {
	return strings.ReplaceAll(providerType, "_", "-")
}
