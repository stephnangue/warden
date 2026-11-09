package dev

import "github.com/spf13/cobra"

// DevCmd groups the commands that work with a playground started by
// `warden server -dev-playground`.
var DevCmd = &cobra.Command{
	Use:   "dev",
	Short: "Try Warden with the dev playground.",
	Long: `
Usage: warden dev <subcommand> [options]

  Work with a playground started by:

      $ warden server -dev-playground

  The playground runs an identity provider and a bank behind Warden, wired
  up and ready. These commands mint the identities to try it with, show the
  scenarios, and read what Warden recorded. They need the root token.

  Start here:

      $ warden dev scenarios

  Mint an agent identity, and a user who lets that agent act for them:

      $ AGENT=$(warden dev jwt agent agent-1)
      $ ALICE=$(warden dev jwt user alice -may-act agent-1)

  See what Warden decided:

      $ warden dev audit -decision deny
`,
}

func init() {
	DevCmd.AddCommand(JWTCmd)
	DevCmd.AddCommand(ScenariosCmd)
	DevCmd.AddCommand(AuditCmd)
}
