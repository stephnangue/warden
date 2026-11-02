package core

import (
	"context"
	"fmt"
	"slices"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// pathIdentityConfig returns sys/identity/config: the namespace's identity
// verdict settings. Sudo (PathsSpecial.Root).
func (b *SystemBackend) pathIdentityConfig() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "identity/config$",
			Fields: map[string]*framework.FieldSchema{
				"unknown_aliases": {
					Type: framework.TypeString,
					Description: `How callers whose native identity no entity claims, or who present none, are treated: ` +
						`"observe" (the default: admitted) or "deny" (refused, and so is a claimed caller whose entity is not ` +
						`governed, unless their mount is exempt). A claimed caller whose entity is suspended or retired is ` +
						`refused in every mode.`,
				},
				"exempt_mounts": {
					Type:        framework.TypeCommaStringSlice,
					Description: `Auth mounts of this namespace, by path (e.g. "auth/github-oidc/"), whose callers unknown_aliases=deny never refuses`,
				},
				"force": {
					Type:        framework.TypeBool,
					Description: "Write a config that would refuse the writer's own requests",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handleIdentityConfigRead, Summary: "Read the identity config"},
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleIdentityConfigWrite, Summary: "Write the identity config"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleIdentityConfigWrite, Summary: "Write the identity config"},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.handleIdentityConfigDelete, Summary: "Reset the identity config"},
			},
			HelpSynopsis: "Read or write the namespace's identity verdict settings",
			HelpDescription: "unknown_aliases decides whether callers whose native identity no entity claims are admitted " +
				"(observe) or refused (deny); exempt_mounts lists the auth mounts deny never applies to. A write sets the " +
				"fields it names and keeps the others; a delete restores the defaults.",
		},
	}
}

// identityConfigToMap renders cfg for a response: each exempt mount by its
// current path, and by accessor, which still names a mount disabled since.
func (b *SystemBackend) identityConfigToMap(cfg *identityConfig) map[string]any {
	exempt := make([]map[string]any, len(cfg.ExemptMounts))
	for i, acc := range cfg.ExemptMounts {
		exempt[i] = map[string]any{"mount": b.core.aliasMountPath(acc), "mount_accessor": acc}
	}
	return map[string]any{
		"unknown_aliases": cfg.mode(),
		"exempt_mounts":   exempt,
	}
}

// identityConfigWarnings says what in cfg has no effect: an exempt mount that
// admits humans (their tickets are never judged by identity), and an exempt
// accessor no mount carries any more.
func (b *SystemBackend) identityConfigWarnings(ctx context.Context, cfg *identityConfig) []string {
	var warnings []string
	for _, acc := range cfg.ExemptMounts {
		path := b.core.aliasMountPath(acc)
		if path == "" {
			warnings = append(warnings, fmt.Sprintf("exempt mount %s names no auth mount any more; it has no effect", acc))
			continue
		}
		if _, kind, err := b.core.resolveAliasMount(ctx, path); err == nil && kind == logical.EntityKindHuman {
			warnings = append(warnings, fmt.Sprintf("exempt mount %s admits humans, whom unknown_aliases never refuses; it has no effect", path))
		}
	}
	return warnings
}

// handleIdentityConfigRead handles GET sys/identity/config.
func (b *SystemBackend) handleIdentityConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.core.identityStore.IdentityConfig(ctx)
	if err != nil {
		return b.entityErrorResponse("", err), nil
	}
	data := b.identityConfigToMap(cfg)
	appendWarnings(data, b.identityConfigWarnings(ctx, cfg)...)
	return b.respondSuccess(data), nil
}

// handleIdentityConfigWrite handles POST and PUT sys/identity/config: the
// fields present replace the stored ones, the others are kept. A config that
// would refuse the writer's own requests is refused unless force.
func (b *SystemBackend) handleIdentityConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.core.identityStore.IdentityConfig(ctx)
	if err != nil {
		return b.entityErrorResponse("", err), nil
	}
	if v, ok := d.GetOk("unknown_aliases"); ok {
		mode, err := parseUnknownAliases(v.(string))
		if err != nil {
			return logical.ErrorResponse(err), nil
		}
		cfg.UnknownAliases = mode
	}
	if v, ok := d.GetOk("exempt_mounts"); ok {
		accessors := make([]string, 0, len(v.([]string)))
		for _, path := range v.([]string) {
			accessor, _, err := b.core.resolveAliasMount(ctx, path)
			if err != nil {
				return logical.ErrorResponse(fmt.Errorf("exempt_mounts: %w", err)), nil
			}
			accessors = append(accessors, accessor)
		}
		slices.Sort(accessors)
		cfg.ExemptMounts = slices.Compact(accessors)
	}

	var warnings []string
	if reason := writerVerdict(ctx, cfg, req.TokenEntry()); reason != "" {
		if !d.Get("force").(bool) {
			return logical.ErrorResponse(logical.ErrConflictf(
				"this config would refuse the writer's own requests (%s); pass force=true to write it anyway", reason)), nil
		}
		warnings = append(warnings, fmt.Sprintf("forced: this config refuses the writer's own requests (%s)", reason))
	}
	if err := b.core.identityStore.SetIdentityConfig(ctx, cfg); err != nil {
		return b.entityErrorResponse("", err), nil
	}
	data := b.identityConfigToMap(cfg)
	appendWarnings(data, warnings...)
	appendWarnings(data, b.identityConfigWarnings(ctx, cfg)...)
	return b.respondSuccess(data), nil
}

// handleIdentityConfigDelete handles DELETE sys/identity/config: the defaults,
// which refuse no one but the suspended and retired.
func (b *SystemBackend) handleIdentityConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.core.identityStore.SetIdentityConfig(ctx, nil); err != nil {
		return b.entityErrorResponse("", err), nil
	}
	cfg, err := b.core.identityStore.IdentityConfig(ctx)
	if err != nil {
		return b.entityErrorResponse("", err), nil
	}
	return b.respondSuccess(b.identityConfigToMap(cfg)), nil
}

// writerVerdict returns the identity verdict cfg, the config of the namespace
// in ctx, would give the writer te: an agent, with the native identity and
// entity its own request resolved. A token no mount issued (root) and a
// human's ticket are never judged, so they are never locked out, and root
// stays the way back. A writer of another namespace (a parent's token writing
// a child's config) is judged by its own namespace's config, not this one.
func writerVerdict(ctx context.Context, cfg *identityConfig, te *logical.TokenEntry) string {
	if te == nil || te.Admission == nil || te.MountAccessor == "" {
		return ""
	}
	if ns, err := namespace.FromContext(ctx); err != nil || ns.ID != te.NamespaceID {
		return ""
	}
	return identityVerdict(cfg, te.Admission, &logical.Membership{Naming: te.Admission.Mount.Load(), Entity: te.Entity})
}
