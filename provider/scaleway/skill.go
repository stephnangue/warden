package scaleway

import _ "embed"

//go:embed skill.md
var skillMD string

// Skill returns the agent-facing skill markdown for the Scaleway provider.
// The content is seeded into the global skill registry the first time a
// Scaleway provider is mounted in the cluster; subsequent mounts are
// no-ops and operator edits to the registered skill are preserved.
func Skill() string {
	return skillMD
}
