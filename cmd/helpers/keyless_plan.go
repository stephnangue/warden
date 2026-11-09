package helpers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/stephnangue/warden/api"
)

// KeylessPlanInput builds a keyless plan request from the command's flags or
// its -json payload; the two are mutually exclusive. specInputs are
// "<spec>/<key>=<value>" pairs, for a source plan's bound specs.
func KeylessPlanInput(jsonFlag, newName string, inputs, specInputs map[string]string) (*api.KeylessPlanInput, error) {
	payload, err := ResolveJSONInput(jsonFlag)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		if err := RejectFlagsWithJSON(true, map[string]bool{
			"-new-name":   newName != "",
			"-input":      len(inputs) > 0,
			"-spec-input": len(specInputs) > 0,
		}); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		in := &api.KeylessPlanInput{}
		if err := json.Unmarshal(raw, in); err != nil {
			return nil, fmt.Errorf("-json: %v: %w", err, ErrInvalidInput)
		}
		return in, nil
	}

	in := &api.KeylessPlanInput{NewName: newName, Target: inputs}
	for k, v := range specInputs {
		spec, key, ok := strings.Cut(k, "/")
		if !ok || spec == "" || key == "" {
			return nil, fmt.Errorf("-spec-input %q: want <spec>/<key>=<value>: %w", k, ErrUsage)
		}
		if in.Specs == nil {
			in.Specs = map[string]map[string]string{}
		}
		if in.Specs[spec] == nil {
			in.Specs[spec] = map[string]string{}
		}
		in.Specs[spec][key] = v
	}
	return in, nil
}

// RenderKeylessPlan renders a keyless plan: as the plan's JSON for -o json, or
// as the steps an operator follows — configure the upstream, create the keyless
// objects, point roles at them, then delete the keyed ones.
func RenderKeylessPlan(kind, name string, plan *api.KeylessPlan) error {
	raw, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	return RenderMap(data, func() { printKeylessPlan(kind, name, plan) })
}

func printKeylessPlan(kind, name string, plan *api.KeylessPlan) {
	w := outWriter
	status := "ready"
	if !plan.Ready {
		status = "blocked"
	}
	fmt.Fprintf(w, "Keyless plan for credential %s %s (%s). Nothing has been written.\n", kind, name, status)

	if len(plan.Blockers) > 0 {
		fmt.Fprintln(w, "\nBlockers — resolve these, then plan again:")
		for _, b := range plan.Blockers {
			fmt.Fprintf(w, "  - %s\n", b)
		}
	}

	if plan.Source == nil && len(plan.Specs) == 0 {
		printNotes(plan.Notes)
		return
	}

	step := 0
	heading := func(title string) {
		step++
		fmt.Fprintf(w, "\n%d. %s\n", step, title)
	}

	if len(plan.Prerequisites) > 0 {
		heading("Configure the upstream to trust Warden")
		for _, p := range plan.Prerequisites {
			fmt.Fprintf(w, "\n  %s — %s\n\n", p.Title, p.Where)
			fmt.Fprintln(w, indent(strings.TrimRight(p.Body, "\n"), "    "))
		}
	}

	heading("Create the keyless objects next to the keyed ones")
	if plan.Source != nil {
		fmt.Fprintf(w, "\n%s\n", indent(createCommand("source", plan.Source.Name, sourcePayload(plan.Source)), "  "))
	}
	for i := range plan.Specs {
		s := &plan.Specs[i]
		fmt.Fprintf(w, "\n%s\n", indent(createCommand("spec", s.Name, specPayload(s)), "  "))
		if s.Behaviour != "" {
			fmt.Fprintf(w, "  # %s\n", s.Behaviour)
		}
		if len(s.Choices) > 1 {
			fmt.Fprintf(w, "  # choice: %s (default %s)\n", strings.Join(s.Choices, " | "), s.Choices[0])
		}
	}

	if len(plan.Specs) > 0 {
		heading("Point each role's credential_spec at its keyless spec")
		for _, s := range plan.Specs {
			fmt.Fprintf(w, "  %s → %s\n", s.Replaces, s.Name)
		}
	}

	heading("Once roles work on the keyless objects, delete the keyed ones")
	fmt.Fprintln(w)
	for _, s := range plan.Specs {
		fmt.Fprintf(w, "  warden cred spec delete %s\n", s.Replaces)
	}
	if plan.Source != nil {
		fmt.Fprintf(w, "  warden cred source delete %s\n", plan.Source.Replaces)
	}
	if len(plan.Leftovers) > 0 {
		fmt.Fprintln(w, "\n  Then delete the credentials they held, which stay valid upstream until you do:")
		for _, l := range plan.Leftovers {
			fmt.Fprintf(w, "\n  - %s (%s)\n    %s\n", l.Kind, l.ID, l.WhereToDelete)
		}
	}

	printNotes(plan.Notes)
}

func printNotes(notes []string) {
	if len(notes) == 0 {
		return
	}
	fmt.Fprintln(outWriter, "\nNotes:")
	for _, n := range notes {
		fmt.Fprintf(outWriter, "  - %s\n", n)
	}
}

func sourcePayload(o *api.KeylessObject) map[string]any {
	return map[string]any{"type": o.Type, "config": o.Config}
}

func specPayload(o *api.KeylessObject) map[string]any {
	p := map[string]any{"type": o.Type, "source": o.Source, "config": o.Config}
	if o.MinTTL != 0 {
		p["min_ttl"] = o.MinTTL
	}
	if o.MaxTTL != 0 {
		p["max_ttl"] = o.MaxTTL
	}
	return p
}

// createCommand renders a create command with its payload as indented JSON in
// single quotes, escaping any single quote the payload holds.
func createCommand(kind, name string, payload map[string]any) string {
	body, _ := json.MarshalIndent(payload, "", "  ")
	quoted := strings.ReplaceAll(string(body), "'", `'\''`)
	return fmt.Sprintf("warden cred %s create %s -json '%s'", kind, name, quoted)
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}
