package identity

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/cmd/helpers"
)

// aliasFlags are the fields an alias command takes: the native identity (its
// auth mount by path, or by accessor where the command accepts one, and its
// name) and the entity it goes to or comes from. -json carries the same
// fields under their payload keys.
type aliasFlags struct {
	mount    string
	accessor string
	name     string
	entity   string
	json     string
}

// aliasCommand describes one alias command's input: the payload key naming
// the entity, which is then required ("to", "from", or "" when the command
// takes none), and whether the mount may be named by accessor.
type aliasCommand struct {
	entityKey  string
	byAccessor bool
}

func (f *aliasFlags) bind(cmd *cobra.Command, ac aliasCommand) {
	fs := cmd.Flags()
	fs.StringVar(&f.mount, "mount", "", `The auth mount the native identity is presented through, by path, e.g. "auth/kubernetes/"`)
	if ac.byAccessor {
		fs.StringVar(&f.accessor, "mount-accessor", "",
			"The auth mount by accessor instead of -mount; it also names a mount disabled since")
	}
	fs.StringVar(&f.name, "name", "", `The native identity, as the mount derives it, e.g. "system:serviceaccount:billing:agent"`)
	switch ac.entityKey {
	case "to":
		fs.StringVar(&f.entity, "to", "", "The entity that claims the native identity")
	case "from":
		fs.StringVar(&f.entity, "from", "", "The entity that claims it now; any other is refused")
	}
	fs.StringVarP(&f.json, "json", "j", "",
		"Full JSON payload — '<json>', '@file.json', or '-' for stdin (mutually exclusive with the typed flags)")
}

// reset restores the zero values. Intended for tests, which reuse the
// package-level commands.
func (f *aliasFlags) reset() { *f = aliasFlags{} }

// input returns the native identity and the entity the command names, from
// -json or the typed flags.
func (f *aliasFlags) input(cmd *cobra.Command, ac aliasCommand) (api.AliasRef, string, error) {
	keys := []string{"mount", "name"}
	if ac.byAccessor {
		keys = append(keys, "mount_accessor")
	}
	if ac.entityKey != "" {
		keys = append(keys, ac.entityKey)
	}

	var ref api.AliasRef
	var entity string
	payload, err := helpers.ResolveJSONInput(f.json)
	if err != nil {
		return ref, "", err
	}
	if payload != nil {
		changed := map[string]bool{}
		for _, flag := range []string{"mount", "mount-accessor", "name", "to", "from"} {
			if cmd.Flags().Lookup(flag) != nil {
				changed["-"+flag] = cmd.Flags().Changed(flag)
			}
		}
		if err := helpers.RejectFlagsWithJSON(true, changed); err != nil {
			return ref, "", err
		}
		fields := map[string]string{}
		for k, v := range payload {
			if !slices.Contains(keys, k) {
				return ref, "", fmt.Errorf("unknown field %q: the payload takes %s: %w", k, strings.Join(keys, ", "), helpers.ErrUsage)
			}
			s, ok := v.(string)
			if !ok {
				return ref, "", fmt.Errorf("%q must be a string: %w", k, helpers.ErrUsage)
			}
			fields[k] = s
		}
		ref = api.AliasRef{Mount: fields["mount"], MountAccessor: fields["mount_accessor"], Name: fields["name"]}
		entity = fields[ac.entityKey]
	} else {
		ref = api.AliasRef{Mount: f.mount, MountAccessor: f.accessor, Name: f.name}
		entity = f.entity
	}

	switch {
	case ref.Mount == "" && ref.MountAccessor == "":
		if ac.byAccessor {
			return ref, "", fmt.Errorf("mount or mount_accessor is required: %w", helpers.ErrUsage)
		}
		return ref, "", fmt.Errorf("mount is required: %w", helpers.ErrUsage)
	case ref.Mount != "" && ref.MountAccessor != "":
		return ref, "", fmt.Errorf("mount and mount_accessor are exclusive: %w", helpers.ErrUsage)
	case ref.Name == "":
		return ref, "", fmt.Errorf("name is required: %w", helpers.ErrUsage)
	case ac.entityKey != "" && entity == "":
		return ref, "", fmt.Errorf("%s is required: %w", ac.entityKey, helpers.ErrUsage)
	}
	if entity != "" {
		if err := validateEntityName(entity); err != nil {
			return ref, "", err
		}
	}
	return ref, entity, nil
}

// aliasMountLabel names ref's mount for a message: its path, or its accessor.
func aliasMountLabel(ref api.AliasRef) string {
	if ref.Mount != "" {
		return ref.Mount
	}
	return ref.MountAccessor
}
