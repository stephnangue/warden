package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// KeylessPlanInput is what a keyless plan is asked for. It carries no secrets:
// the server refuses an input that sets a secret field.
type KeylessPlanInput struct {
	// NewName names the proposed source (or spec); default "<name>-keyless".
	NewName string `json:"new_name,omitempty"`

	// Target sets inputs for the proposed source (or spec).
	Target map[string]string `json:"target,omitempty"`

	// Specs sets inputs per bound spec of a source, keyed by the keyed spec's
	// name; its "name" key names the proposed spec.
	Specs map[string]map[string]string `json:"specs,omitempty"`
}

// KeylessObject is a source or spec a keyless plan proposes to create.
type KeylessObject struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Source    string            `json:"source,omitempty"`
	Replaces  string            `json:"replaces"`
	Config    map[string]string `json:"config"`
	MinTTL    int64             `json:"min_ttl,omitempty"`
	MaxTTL    int64             `json:"max_ttl,omitempty"`
	Behaviour string            `json:"behaviour,omitempty"`
	Choices   []string          `json:"choices,omitempty"`
}

// KeylessPrerequisite is one piece of upstream configuration a keyless source
// needs, rendered as Format ("json", "shell", "yaml" or "text").
type KeylessPrerequisite struct {
	Title  string `json:"title"`
	Where  string `json:"where"`
	Format string `json:"format"`
	Body   string `json:"body"`
}

// KeylessLeftover is a credential the keyed objects hold that the keyless ones
// do not use; nothing deletes it automatically.
type KeylessLeftover struct {
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	WhereToDelete string `json:"where_to_delete"`
}

// KeylessPlan is a keyless plan: the objects to create, what the upstream must
// trust first, and what to delete once roles use the new objects. Ready is
// false while Blockers is non-empty.
type KeylessPlan struct {
	Source        *KeylessObject        `json:"source,omitempty"`
	Specs         []KeylessObject       `json:"specs"`
	Prerequisites []KeylessPrerequisite `json:"prerequisites,omitempty"`
	Leftovers     []KeylessLeftover     `json:"leftovers,omitempty"`
	Notes         []string              `json:"notes,omitempty"`
	Blockers      []string              `json:"blockers,omitempty"`
	Ready         bool                  `json:"ready"`
}

// PlanKeylessCredentialSource plans the keyless replacement of a credential
// source and its specs. It writes nothing.
func (c *Sys) PlanKeylessCredentialSource(name string, input *KeylessPlanInput) (*KeylessPlan, error) {
	return c.PlanKeylessCredentialSourceWithContext(context.Background(), name, input)
}

// PlanKeylessCredentialSourceWithContext plans a keyless source with context.
func (c *Sys) PlanKeylessCredentialSourceWithContext(ctx context.Context, name string, input *KeylessPlanInput) (*KeylessPlan, error) {
	return c.planKeyless(ctx, fmt.Sprintf("/v1/sys/cred/sources/%s/keyless-plan", name), input)
}

// PlanKeylessCredentialSpec plans the keyless replacement of a credential spec.
// It writes nothing.
func (c *Sys) PlanKeylessCredentialSpec(name string, input *KeylessPlanInput) (*KeylessPlan, error) {
	return c.PlanKeylessCredentialSpecWithContext(context.Background(), name, input)
}

// PlanKeylessCredentialSpecWithContext plans a keyless spec with context.
func (c *Sys) PlanKeylessCredentialSpecWithContext(ctx context.Context, name string, input *KeylessPlanInput) (*KeylessPlan, error) {
	return c.planKeyless(ctx, fmt.Sprintf("/v1/sys/cred/specs/%s/keyless-plan", name), input)
}

func (c *Sys) planKeyless(ctx context.Context, path string, input *KeylessPlanInput) (*KeylessPlan, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	if input == nil {
		input = &KeylessPlanInput{}
	}

	r := c.c.NewRequest(http.MethodPost, path)
	if err := r.SetJSONBody(input); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resource, err := ParseResource(resp.Body)
	if err != nil {
		return nil, err
	}
	if resource == nil || resource.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	raw, err := json.Marshal(resource.Data)
	if err != nil {
		return nil, err
	}
	plan := &KeylessPlan{}
	if err := json.Unmarshal(raw, plan); err != nil {
		return nil, fmt.Errorf("decoding keyless plan: %w", err)
	}
	return plan, nil
}
