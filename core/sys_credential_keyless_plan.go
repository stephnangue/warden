package core

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

func keylessPlanFields(nameDescription string) map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: nameDescription,
			Required:    true,
		},
		"new_name": {
			Type:        framework.TypeString,
			Description: "Name for the proposed keyless object (default: <name>-keyless)",
		},
		"target": {
			Type:        framework.TypeMap,
			Description: "Inputs for the proposed object, such as a JWT role, an audience or a secret_spec. Secret fields are refused.",
		},
		"specs": {
			Type:        framework.TypeMap,
			Description: "Inputs per bound spec, keyed by the keyed spec's name; each spec's \"name\" input names its proposed replacement.",
		},
	}
}

// handleCredentialSourceKeylessPlan handles POST
// /sys/cred/sources/{name}/keyless-plan.
func (b *SystemBackend) handleCredentialSourceKeylessPlan(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	in, err := keylessPlanInputs(d)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	plan, err := b.core.PlanKeylessSource(ctx, d.Get("name").(string), in)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	return b.respondSuccess(b.keylessPlanData(plan)), nil
}

// handleCredentialSpecKeylessPlan handles POST
// /sys/cred/specs/{name}/keyless-plan.
func (b *SystemBackend) handleCredentialSpecKeylessPlan(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	in, err := keylessPlanInputs(d)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	if len(in.Specs) > 0 {
		return logical.ErrorResponse(logical.ErrBadRequest("specs applies to a source plan; set the spec's inputs in target")), nil
	}
	plan, err := b.core.PlanKeylessSpec(ctx, d.Get("name").(string), in)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	return b.respondSuccess(b.keylessPlanData(plan)), nil
}

func keylessPlanInputs(d *framework.FieldData) (KeylessPlanInputs, error) {
	in := KeylessPlanInputs{Name: d.Get("new_name").(string)}
	if raw, ok := d.GetOk("target"); ok {
		in.Target = convertToStringMap(raw.(map[string]any))
	}
	if raw, ok := d.GetOk("specs"); ok {
		specs := raw.(map[string]any)
		in.Specs = make(map[string]map[string]string, len(specs))
		for name, v := range specs {
			m, ok := v.(map[string]any)
			if !ok {
				return in, logical.ErrBadRequestf("specs.%s must be an object of inputs", name)
			}
			in.Specs[name] = convertToStringMap(m)
		}
	}
	return in, nil
}

// keylessPlanData lays a plan out as response data. A planned config holds no
// stored secret — a plan removes those and refuses inputs that set one — but it
// keeps every other key of the keyed config, and some of those the read path
// masks, such as an api_key spec's operator-declared fields, which may be a
// second secret. They are masked here too, so a plan shows nothing a read would
// not; the operator copies them from the keyed object.
func (b *SystemBackend) keylessPlanData(plan *KeylessPlan) map[string]any {
	var masked []string
	maskObject := func(o KeylessObject, isSource bool) map[string]any {
		var cfg map[string]string
		if isSource {
			cfg = b.maskSourceConfig(o.Type, o.Config)
		} else {
			cfg = b.maskSpecConfig(o.Type, o.Config)
		}
		for k, v := range cfg {
			switch {
			case k == "ca_data":
				// A CA certificate is masked for tidiness, not secrecy; keeping it
				// leaves the create command ready to paste.
				cfg[k] = o.Config[k]
			case v == maskValue && o.Config[k] != maskValue:
				masked = append(masked, fmt.Sprintf("%s (from %s)", k, o.Replaces))
			}
		}
		o.Config = cfg
		return keylessObjectData(o)
	}

	specs := make([]any, 0, len(plan.Specs))
	for _, s := range plan.Specs {
		specs = append(specs, maskObject(s, false))
	}
	data := map[string]any{"specs": specs}
	if plan.Source != nil {
		data["source"] = maskObject(*plan.Source, true)
	}

	notes := plan.Notes
	if len(masked) > 0 {
		sort.Strings(masked)
		notes = append(slices.Clone(notes), fmt.Sprintf(
			"values shown as %s are masked as they are on a read; copy them from the keyed object before creating: %s",
			maskValue, strings.Join(masked, ", ")))
	}
	data["prerequisites"] = plan.Prerequisites
	data["leftovers"] = plan.Leftovers
	data["notes"] = notes
	data["blockers"] = plan.Blockers
	data["ready"] = len(plan.Blockers) == 0
	return data
}

func keylessObjectData(o KeylessObject) map[string]any {
	out := map[string]any{
		"name":     o.Name,
		"type":     o.Type,
		"replaces": o.Replaces,
		"config":   o.Config,
	}
	if o.Source != "" {
		out["source"] = o.Source
	}
	if o.MinTTL != 0 {
		out["min_ttl"] = o.MinTTL
	}
	if o.MaxTTL != 0 {
		out["max_ttl"] = o.MaxTTL
	}
	if o.Behaviour != "" {
		out["behaviour"] = o.Behaviour
	}
	if len(o.Choices) > 0 {
		out["choices"] = o.Choices
	}
	return out
}
