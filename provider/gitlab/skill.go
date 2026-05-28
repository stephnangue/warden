package gitlab

import _ "embed"

//go:embed skill.md
var skillMD string

// Skill returns the agent-facing markdown for the gitlab provider, seeded
// into the global skill registry on first mount.
func Skill() string {
	return skillMD
}
